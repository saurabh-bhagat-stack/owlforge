"""Interactive scan dashboard (Textual).

Full-screen, keyboard- and mouse-driven view shown with `owlforge run -D`:
  * a status bar (target / phase / elapsed / live counts),
  * a SCROLLABLE, SELECTABLE findings table (Enter or click a row -> detail screen),
  * a SCROLLABLE event log.

The scan runs in a background worker thread so the UI stays responsive; the Emitter
posts events to the app through a thread-safe sink, and the findings table refreshes from
the store on a timer (so confirmations from the eager validator appear live). The app
stays open when the scan finishes so findings can be browsed; press q to quit.
"""

from __future__ import annotations

import time

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, RichLog, Static

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
              "low": "cyan", "info": "dim"}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_STATUS_STYLE = {"validated": "bold green", "candidate": "yellow", "manual": "yellow"}

_PHASES = (
    ("reporting", "reporting"), ("validation", "validation"), ("deepen", "deepening"),
    ("final validation", "validation"), ("orchestrator", "hunt"), ("[specialist:", "hunt"),
    ("pre-probe", "hunt"), ("oast", "deterministic passes"), ("access-control", "deterministic passes"),
    ("csrf", "deterministic passes"), ("smuggle", "deterministic passes"),
    ("graphql", "deterministic passes"), ("client-side", "deterministic passes"),
    ("collapse", "reporting"), ("dedupe", "reporting"),
)


def _phase_of(message: str) -> str | None:
    low = (message or "").lower()
    for key, label in _PHASES:
        if key in low:
            return label
    return None


class _TuiSink:
    """Emitter dashboard-sink: forwards events to the app on the UI thread."""

    def __init__(self, app: ScanApp) -> None:
        self.app = app

    def handle(self, type_: str, message: str) -> None:
        try:
            self.app.call_from_thread(self.app.on_scan_event, type_, message)
        except Exception:
            pass


class FindingDetail(ModalScreen):
    """Scrollable detail view for one finding."""

    BINDINGS = [Binding("escape,q", "dismiss", "Close")]

    def __init__(self, finding: dict) -> None:
        super().__init__()
        self._f = finding

    def compose(self) -> ComposeResult:
        f = self._f
        t = Text()
        sev = (f.get("severity") or "").lower()
        t.append(f"{sev.upper()}  ", style=_SEV_STYLE.get(sev, "white"))
        t.append(f"{f.get('title') or ''}\n", style="bold")
        t.append(f"status: {f.get('status')}   confidence: {f.get('confidence')}\n", style="dim")
        t.append(f"{f.get('method') or ''} {f.get('endpoint') or ''}\n\n", style="cyan")
        for label in ("technical_analysis", "proof_of_concept", "impact", "remediation",
                      "validation_note", "evidence"):
            val = f.get(label)
            if val:
                t.append(f"# {label.replace('_', ' ')}\n", style="bold yellow")
                t.append(f"{val}\n\n", style="white")
        yield VerticalScroll(Static(t), id="detail")

    def action_dismiss(self) -> None:
        self.app.pop_screen()


class ScanApp(App):
    CSS = """
    #status { height: 3; background: $panel; color: $text; padding: 0 1; border: round $primary; }
    #findings { width: 55%; border: round $accent; }
    #log { border: round $surface; }
    #detail { padding: 1 2; }
    """
    BINDINGS = [
        Binding("q,ctrl+c", "quit", "Quit"),
        Binding("d", "open", "Details"),
    ]

    def __init__(self, assessment_id: str, target: str, model: str, scan_fn) -> None:
        super().__init__()
        self.aid = assessment_id
        self.target = target
        self.model = model
        self.scan_fn = scan_fn
        self._started = time.time()
        self._phase = "starting"
        self._done = False
        self.result_status = "completed"
        self.result_summary = ""
        self.result_report = None

    def compose(self) -> ComposeResult:
        yield Static(id="status")
        with Horizontal():
            yield DataTable(id="findings", zebra_stripes=True, cursor_type="row")
            yield RichLog(id="log", highlight=False, markup=False, wrap=False, max_lines=2000)
        yield Footer()

    def on_mount(self) -> None:
        dt = self.query_one("#findings", DataTable)
        dt.add_columns("SEV", "STATUS", "FINDING", "ENDPOINT")
        dt.focus()
        self.set_interval(0.6, self._refresh)
        self._update_status()
        self.run_worker(self._scan, thread=True, exclusive=True)

    # ---- scan worker (background thread) --------------------------------------------
    def _scan(self) -> None:
        from owlforge.engine.events import Emitter
        emit = Emitter(self.aid, dashboard=_TuiSink(self), persist=True)
        try:
            summary, report = self.scan_fn(emit)
            self.result_summary, self.result_report = summary, report
        except KeyboardInterrupt:
            self.result_status = "stopped"
        except Exception as e:  # surface, don't crash the UI
            self.result_status = "failed"
            try:
                self.call_from_thread(self._write_log, "error", f"{type(e).__name__}: {e}")
            except Exception:
                pass
        try:
            self.call_from_thread(self._scan_done)
        except Exception:
            pass

    # ---- UI-thread handlers ----------------------------------------------------------
    def on_scan_event(self, type_: str, message: str) -> None:
        self._write_log(type_, message)
        if type_ == "status":
            self._phase = _phase_of(message) or self._phase
            self._update_status()

    def _write_log(self, type_: str, message: str) -> None:
        try:
            self.query_one("#log", RichLog).write(f"[{type_}] {message}"[:1000])
        except Exception:
            pass

    def _findings(self) -> list[dict]:
        try:
            from sqlmodel import select

            from owlforge.store.db import session
            from owlforge.store.models import Finding
            with session() as s:
                rows = s.exec(select(Finding).where(Finding.assessment_id == self.aid)).all()
            keep = [f for f in rows if f.status in ("validated", "candidate", "manual")]
            keep.sort(key=lambda f: (f.status != "validated",
                                     -_SEV_RANK.get((f.severity or "").lower(), 0)))
            return [{"id": f.id, "severity": f.severity or "info", "status": f.status,
                     "title": f.title or "", "endpoint": f.endpoint or "",
                     "method": f.method, "confidence": f.confidence,
                     "technical_analysis": f.technical_analysis,
                     "proof_of_concept": f.proof_of_concept, "impact": f.impact,
                     "remediation": f.remediation, "validation_note": f.validation_note,
                     "evidence": f.evidence} for f in keep]
        except Exception:
            return []

    def _refresh(self) -> None:
        dt = self.query_one("#findings", DataTable)
        rows = self._findings()
        self._row_cache = {f["id"]: f for f in rows}
        existing = set(dt.rows.keys())
        for f in rows:
            if f["id"] in existing:
                continue
            sev = Text(f["severity"].upper()[:8], style=_SEV_STYLE.get(f["severity"].lower(), "white"))
            st = Text(f["status"][:9], style=_STATUS_STYLE.get(f["status"], "white"))
            dt.add_row(sev, st, (f["title"] or "")[:60], (f["endpoint"] or "")[:60], key=f["id"])
        self._update_status()

    def _update_status(self) -> None:
        el = int(time.time() - self._started)
        rows = getattr(self, "_row_cache", {})
        v = sum(1 for f in rows.values() if f["status"] == "validated")
        c = sum(1 for f in rows.values() if f["status"] in ("candidate", "manual"))
        t = Text()
        t.append("owlforge  ", style="bold cyan")
        t.append(f"{self.target}\n", style="white")
        t.append(f"phase {self._phase}", style="bold yellow")
        t.append(f"   {el // 60:02d}:{el % 60:02d}", style="dim")
        t.append(f"   {v} validated", style="bold green")
        t.append(f" / {c} candidate", style="yellow")
        if self._done:
            t.append(f"   [{self.result_status.upper()} — q to quit]", style="bold")
        try:
            self.query_one("#status", Static).update(t)
        except Exception:
            pass

    def _scan_done(self) -> None:
        self._done = True
        self._refresh()
        self._phase = "complete"
        self._update_status()

    def action_open(self) -> None:
        dt = self.query_one("#findings", DataTable)
        if dt.row_count == 0:
            return
        try:
            key = dt.coordinate_to_cell_key(dt.cursor_coordinate).row_key.value
        except Exception:
            return
        f = getattr(self, "_row_cache", {}).get(key)
        if f:
            self.push_screen(FindingDetail(f))

    def on_data_table_row_selected(self, event) -> None:
        f = getattr(self, "_row_cache", {}).get(event.row_key.value)
        if f:
            self.push_screen(FindingDetail(f))


def run_scan_tui(assessment_id: str, target: str, model: str, scan_fn):
    """Run the scan inside the interactive dashboard. scan_fn(emit) -> (summary, report).
    Returns (status, summary, report_path) after the user quits."""
    app = ScanApp(assessment_id, target, model, scan_fn)
    app.run()
    return app.result_status, app.result_summary, app.result_report
