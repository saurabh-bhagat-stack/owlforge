"""Event emitter: persists events to the store and streams them to the console."""

from __future__ import annotations

import secrets

from rich.console import Console

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
                 quiet: bool = False) -> None:
        self.assessment_id = assessment_id
        self.console = console or Console()
        self.persist = persist
        self.quiet = quiet

    def __call__(self, type_: str, message: str, **data) -> None:
        if not self.quiet:
            label = type_.upper().replace("_", " ")
            style = _STYLE.get(type_, "white")
            self.console.print(f"[{style}]\\[{label}][/] {message}")
        if not self.persist:
            return
        try:
            with session() as s:
                s.add(Event(id=f"ev_{secrets.token_hex(5)}", assessment_id=self.assessment_id,
                            type=type_, message=message, data=data or {}))
                s.commit()
        except Exception:
            pass  # event persistence is best-effort; never break the loop
