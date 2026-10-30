"""Event emitter: persists events to the store and streams them to the console."""

from __future__ import annotations

import secrets

from rich.console import Console
from rich.markup import escape

from owlforge.store.db import session
from owlforge.store.models import Event

_STYLE = {
    "think": "dim cyan",
    "assistant": "white",
    "tool_call": "yellow",
    "tool_result": "green",
    "note": "magenta",
    "finish": "bold green",
    "status": "bold blue",
    "log": "dim",
    "error": "bold red",
}


class Emitter:
    def __init__(self, assessment_id: str, console: Console | None = None, persist: bool = True,
                 quiet: bool = False, dashboard=None) -> None:
        self.assessment_id = assessment_id
        self.console = console or Console()
        self.persist = persist
        self.quiet = quiet
        self.dashboard = dashboard
        self._last_key: tuple[str, str] | None = None
        self._dups = 0

    def __call__(self, type_: str, message: str, **data) -> None:
        if self.dashboard is not None:
            # live dashboard owns the screen -> feed it instead of printing lines
            try:
                self.dashboard.handle(type_, message)
            except Exception:
                pass
        elif not self.quiet:
            # collapse runs of identical consecutive lines (e.g. repeated recon
            # crawl lines, or a stuck loop) into a single '(repeated xN)' notice
            key = (type_, message)
            if key == self._last_key:
                self._dups += 1
            else:
                if self._dups:
                    self.console.print(f"[dim]  (last line repeated x{self._dups} more)[/]")
                    self._dups = 0
                label = type_.upper().replace("_", " ")
                style = _STYLE.get(type_, "white")
                # escape the dynamic message: target/model text may contain [..] which Rich
                # would parse as markup (a stray tag crashed whole runs)
                self.console.print(f"[{style}]\\[{label}][/] {escape(str(message))}")
                self._last_key = key
        if not self.persist:
            return
        try:
            with session() as s:
                s.add(Event(id=f"ev_{secrets.token_hex(5)}", assessment_id=self.assessment_id,
                            type=type_, message=message, data=data or {}))
                s.commit()
        except Exception:
            pass  # event persistence is best-effort; never break the loop
