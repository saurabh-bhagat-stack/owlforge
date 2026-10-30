"""Event emitter: persists events to the store and streams them to the console.

The console stream renders through the shared `narrator`, so the plain terminal, the Textual TUI and
the web console all tell the same first-person story. Passive hygiene findings are folded into a
single notice instead of flooding the stream, and the whole run is mirrored to a copyable
transcript.md in the assessment dir (the TUI itself can't be selected/copied).
"""

from __future__ import annotations

import secrets

from rich.console import Console
from rich.markup import escape

from owlforge.engine import narrator
from owlforge.store.db import session
from owlforge.store.models import Event


class Emitter:
    def __init__(self, assessment_id: str, console: Console | None = None, persist: bool = True,
                 quiet: bool = False, dashboard=None, web=None) -> None:
        self.assessment_id = assessment_id
        self.console = console or Console()
        self.persist = persist
        self.quiet = quiet
        self.dashboard = dashboard
        self.web = web
        self._last_key: tuple[str, str] | None = None
        self._dups = 0
        self._hygiene = 0
        self._transcript = None
        if persist and not quiet:
            try:
                self._transcript = narrator.Transcript(assessment_id)
            except Exception:
                self._transcript = None

    def _render(self, line: narrator.NarratedLine) -> None:
        # fold passive hygiene findings: announce once, then stay quiet (they live in the report)
        if line.hygiene:
            self._hygiene += 1
            if self._hygiene == 1:
                self.console.print("[dim]  note  security hygiene — collecting passive issues "
                                   "(missing headers, cookie flags, version banner); grouped in the "
                                   "report[/]")
            return
        key = (line.tag, line.body)
        if key == self._last_key:
            self._dups += 1
            return
        if self._dups:
            self.console.print(f"[dim]  (last line repeated x{self._dups} more)[/]")
            self._dups = 0
        self.console.print(f"[{line.tag_style}]{escape(line.tag)}[/]"
                           f"[{line.body_style}]{escape(str(line.body))}[/]")
        self._last_key = key

    def __call__(self, type_: str, message: str, **data) -> None:
        try:
            line = narrator.narrate(type_, message, data or None)
        except Exception:
            line = None

        if self.dashboard is not None:
            # live dashboard owns the screen -> feed it instead of printing lines
            try:
                self.dashboard.handle(type_, message)
            except Exception:
                pass
        elif not self.quiet and line is not None:
            self._render(line)

        if self._transcript is not None and line is not None:
            try:
                self._transcript.write(line, narrator.phase_of(message))
            except Exception:
                pass

        if self.web is not None and line is not None:
            try:
                self.web.push(type_, message, line)
            except Exception:
                pass

        if not self.persist:
            return
        try:
            with session() as s:
                s.add(Event(id=f"ev_{secrets.token_hex(5)}", assessment_id=self.assessment_id,
                            type=type_, message=message, data=data or {}))
                s.commit()
        except Exception:
            pass  # event persistence is best-effort; never break the loop
