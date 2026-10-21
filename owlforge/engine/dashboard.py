"""Live scan dashboard — a full-screen rich.Live view driven by the event stream.

Layout:
  * header  — wordmark, target, model, phase, elapsed
  * body    — left: current activity + live counts; right: findings table (severity-coloured,
              validated first), read from the store so confirmations appear the moment the
              eager validator flips a candidate to validated
  * log     — the most recent event lines (the same stream that used to scroll)

Only engaged on an interactive terminal; non-TTY/CI falls back to plain log lines (the
Emitter handles that). State is mutated by the Emitter; rich.Live re-renders on a timer.
"""

from __future__ import annotations

import time
from collections import deque

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
              "low": "cyan", "info": "dim"}
_STATUS_STYLE = {"validated": "bold green", "candidate": "yellow", "manual": "yellow",
                 "false_positive": "dim strike", "duplicate": "dim"}
_LOG_STYLE = {"think": "dim cyan", "assistant": "white", "tool_call": "yellow",
              "tool_result": "green", "note": "magenta", "finish": "bold green",
              "status": "blue", "log": "dim", "error": "bold red",
              "finding": "bold magenta", "finding_validated": "bold green",
              "finding_rejected": "dim"}

# status-message substrings -> coarse phase label (best-effort; display only)
_PHASES = (
    ("reporting", "reporting"),
    ("validation", "validation"),
    ("deepen", "deepening"),
    ("orchestrator", "hunt"),
    ("[specialist:", "hunt"),
    ("pre-probe", "hunt"),
    ("oast", "deterministic passes"),
    ("access-control", "deterministic passes"),
    ("csrf", "deterministic passes"),
    ("smuggle", "deterministic passes"),
    ("graphql", "deterministic passes"),
    ("business-logic", "deterministic passes"),
    ("session", "deterministic passes"),
    ("client-side", "deterministic passes"),
    ("collapse", "reporting"),
    ("dedupe", "reporting"),
)


class Dashboard:
    def __init__(self, assessment_id: str, target: str, model: str, console) -> None:
        self.aid = assessment_id
        self.target = target
        self.model = model
        self.console = console
        self.phase = "starting"
        self.activity = "warming up"
        self.started = time.time()
        self.log_lines: deque[tuple[str, str]] = deque(maxlen=500)
        self._live: Live | None = None
        self._fcache: list[tuple] = []
        self._fcache_t = 0.0

    # ---- lifecycle -------------------------------------------------------------------
    def __enter__(self) -> Dashboard:
        self._live = Live(self, console=self.console, refresh_per_second=6, screen=True)
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live is not None:
            self._live.__exit__(*exc)
            self._live = None

    # ---- event sink (called by the Emitter) -----------------------------------------
    def handle(self, type_: str, message: str) -> None:
        self.log_lines.append((type_, message))
        if type_ == "status":
            low = message.lower()
            for key, label in _PHASES:
                if key in low:
                    self.phase = label
                    break
            self.activity = message.strip()

    # ---- findings (from the store, lightly cached) -----------------------------------
    def _findings(self) -> list[tuple]:
        now = time.time()
        if now - self._fcache_t < 0.4:
            return self._fcache
        try:
            from sqlmodel import select

            from owlforge.store.db import session
            from owlforge.store.models import Finding
            with session() as s:
                rows = s.exec(select(Finding).where(Finding.assessment_id == self.aid)).all()
            keep = [f for f in rows if f.status in ("validated", "candidate", "manual")]
            keep.sort(key=lambda f: (f.status != "validated",
                                     -_SEV_RANK.get((f.severity or "").lower(), 0)))
            self._fcache = [(f.severity or "info", f.status, f.title or "", f.endpoint or "")
                            for f in keep]
            self._fcache_t = now
        except Exception:
            pass
        return self._fcache

    # ---- rendering -------------------------------------------------------------------
    def _header(self):
        el = int(time.time() - self.started)
        line = Text()
        line.append("owlforge ", style="bold cyan")
        line.append(f"· {self.target}\n", style="white")
        line.append(f"model {self.model}", style="dim")
        line.append("   phase ", style="dim")
        line.append(f"{self.phase}", style="bold yellow")
        line.append(f"   elapsed {el // 60:02d}:{el % 60:02d}", style="dim")
        return Panel(line, border_style="cyan", padding=(0, 1))

    def _activity_panel(self):
        rows = self._findings()
        v = sum(1 for r in rows if r[1] == "validated")
        c = len(rows) - v
        body = Text()
        body.append("current\n", style="dim")
        body.append((self.activity or "")[:400] + "\n\n", style="white")
        body.append("findings  ", style="dim")
        body.append(f"{v} validated", style="bold green")
        body.append("  /  ", style="dim")
        body.append(f"{c} candidate", style="yellow")
        return Panel(body, title="activity", border_style="blue", padding=(0, 1))

    def _findings_panel(self):
        rows = self._findings()
        t = Table.grid(padding=(0, 1), expand=True)
        t.add_column(width=8)
        t.add_column(width=10)
        t.add_column(ratio=1, no_wrap=True)
        t.add_row(Text("SEV", style="dim"), Text("STATUS", style="dim"), Text("FINDING", style="dim"))
        avail = max(4, self.console.height - 16)
        for sev, status, title, endpoint in rows[:avail]:
            sev_t = Text(sev.upper()[:7], style=_SEV_STYLE.get(sev.lower(), "white"))
            st_t = Text(status[:9], style=_STATUS_STYLE.get(status, "white"))
            label = title if not endpoint else f"{title}  [dim]{endpoint}[/dim]"
            t.add_row(sev_t, st_t, Text.from_markup(label[:200]))
        if not rows:
            t.add_row(Text("—", style="dim"), Text("", style="dim"), Text("no findings yet", style="dim"))
        return Panel(t, title=f"findings ({len(rows)})", border_style="magenta", padding=(0, 1))

    def _log_panel(self):
        avail = max(5, self.console.height - 20)
        lines = list(self.log_lines)[-avail:]
        text = Text()
        for i, (type_, message) in enumerate(lines):
            style = _LOG_STYLE.get(type_, "white")
            tag = type_.upper().replace("_", " ")
            text.append(f"[{tag}] ", style=style)
            text.append(message[:400], style="white")
            if i != len(lines) - 1:
                text.append("\n")
        return Panel(text, title="events", border_style="dim", padding=(0, 1))

    def __rich__(self):
        layout = Layout()
        layout.split_column(
            Layout(self._header(), name="header", size=4),
            Layout(name="body", size=min(14, max(8, self.console.height // 3))),
            Layout(self._log_panel(), name="log"),
        )
        layout["body"].split_row(
            Layout(self._activity_panel(), name="activity", ratio=1),
            Layout(self._findings_panel(), name="findings", ratio=2),
        )
        return layout
