"""Interactive scan dashboard (Textual) — narrative activity feed.

Shown with `owlforge run -D`. Responsive grid:
  * status bar + phase progress,
  * a NARRATIVE activity feed (what owlforge is doing and why — deterministic lines from
    real events; the agent's own reasoning is shown dim and tagged `thinking`, never as a
    proven fact),
  * a scrollable/selectable findings table (Enter/click -> detail),
  * a "current target" card (endpoint, params, class, turn),
  * a surface panel (discovered endpoints + params),
  * a persistent steer input (type a note; the orchestrator folds it into guidance),
  * `L` opens the raw tool-event log.

The scan runs in a daemon thread so the UI stays responsive and Ctrl-C exits cleanly.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Input, RichLog, Static

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_STATUS_STYLE = {"validated": "bold green", "candidate": "yellow", "manual": "yellow"}

# coarse phase ordering for the progress bar
_STAGES = ["starting", "recon", "hunt", "deterministic passes", "validation", "reporting", "complete"]
_PHASES = (
    ("reporting", "reporting"), ("collapse", "reporting"), ("dedupe", "reporting"),
    ("final validation", "validation"), ("validation", "validation"), ("deepen", "validation"),
    ("oast", "deterministic passes"), ("access-control", "deterministic passes"),
    ("csrf", "deterministic passes"), ("cors", "deterministic passes"),
    ("smuggle", "deterministic passes"), ("graphql", "deterministic passes"),
    ("session", "deterministic passes"), ("client-side", "deterministic passes"),
    ("business-logic", "deterministic passes"),
    ("orchestrator", "hunt"), ("[specialist:", "hunt"), ("pre-probe", "hunt"), ("recon", "recon"),
)


def _phase_of(message: str) -> str | None:
    low = (message or "").lower()
    for key, label in _PHASES:
        if key in low:
            return label
    return None


# ----------------------------------------------------------------------------------------
# Narration: map a raw (type, message) event to a human activity line (or None to skip).
# Deterministic — it only re-phrases facts already in the event; it never invents anything.
# ----------------------------------------------------------------------------------------
_SPEC_TITLES = {"sqli": "SQL injection", "xss": "XSS", "access_control": "access-control",
                "ssrf_redirect": "SSRF/redirect", "rce": "RCE", "ssti": "template injection",
                "xxe": "XXE", "path_traversal": "path traversal", "open_redirect": "open redirect",
                "csrf": "CSRF", "nosql": "NoSQL", "graphql": "GraphQL", "crlf": "CRLF",
                "file_upload": "file upload", "deserialization": "deserialization"}
_SPEC_RE = re.compile(r"\[specialist:([a-z_]+)\]\s*(.*)", re.I)
_HTTP_RE = re.compile(r"http_request\s+([A-Z]+)\s+(\S+)")


def _pretty_status(m: str, low: str) -> tuple[str, str, str, str] | None:
    """Turn a terse engine status string into a human, talkative line:
    (tag, tag_style, body, body_style). None -> caller uses a dim default."""
    def after(key: str) -> str:
        return m.split(key, 1)[-1].strip() if key in low else m.strip()

    # --- recon ---------------------------------------------------------------------------
    if low.startswith("unauth recon"):
        return ("recon  ", "bold cyan", "sizing up the app as an anonymous visitor first", "white")
    if "recon: crawled" in low:
        return ("recon  ", "bold cyan", "crawled the site — " + m.split("crawled", 1)[-1].strip(), "white")
    if low.startswith("content discovery"):
        return ("recon  ", "cyan", "brute-forced hidden paths — found " + after("content discovery:"), "white")
    if low.startswith("katana"):
        return ("recon  ", "cyan", "JS-aware crawl turned up " + after("katana:"), "white")
    if low.startswith("js recon"):
        return ("recon  ", "cyan", "mined the JavaScript — " + after("js recon:"), "white")
    if "interactive map" in low:
        return ("recon  ", "cyan", "drove the app in a real browser to catch JS/XHR requests — "
                + after("interactive map:"), "white")
    if low.startswith("waf:"):
        return ("recon  ", "cyan", "fingerprinted a WAF/CDN: " + after("waf:"), "white")
    if low.startswith("passive:"):
        return ("recon  ", "cyan", "noted " + after("passive:"), "white")
    if low.startswith("understand") or "scanning pages/js/files for secrets" in low:
        return ("secrets  ", "cyan", "scanning pages, JS & files for leaked secrets and credentials", "white")
    if "browser-logged-in" in low or ("harvested" in low and "credential" in low):
        cred = re.search(r"\(([^)]+)\)", m)
        creds = cred.group(1) if cred else "an account shown on the page"
        return ("auth ✓ ", "bold green",
                f"logged in with credentials found on the page — {creds}", "white")
    if low.startswith("auth:"):
        return ("auth  ", "bold green", after("auth:"), "white")
    if low.startswith("recon-summary:"):
        return ("recon ✓ ", "bold cyan", "recon complete — " + after("recon-summary:"), "white")
    if low.startswith("surface:"):
        return ("surface  ", "bold green", after("surface:"), "white")
    if "auth recon" in low and "re-mapping" in low:
        return ("recon  ", "cyan", "re-mapping the surface while logged in", "white")

    # --- seeding (acting like a tester: make our own data to attack) ----------------------
    if low.startswith("seed:"):
        r = after("seed:")
        if "logged in" in r:
            r = "registered a throwaway account and logged in (two-step)"
        elif "registered a throwaway" in r or "registered (" in r and "session" in r:
            r = "registered a throwaway account to test with"
        elif "created a test object" in r:
            r = "created a test object to attack — " + r.split("->", 1)[-1].strip()
        elif "could not establish" in r:
            r = "registered, but could not get a session (login step needed)"
        elif "provisioned a second" in r:
            r = "made a 2nd account so we can test one user against another (IDOR)"
        return ("seed  ", "magenta", r, "white")

    # --- nuclei / API spec ---------------------------------------------------------------
    if low.startswith("nuclei:"):
        return ("nuclei  ", "cyan", "ran the CVE/misconfig template set — " + after("nuclei:"), "white")
    if low.startswith("spec:"):
        return ("api-spec  ", "cyan", "loaded " + after("spec:") + " from the API description", "white")
    if low.startswith("api-auth:"):
        return ("api-auth  ", "cyan", "checking spec-protected ops for missing auth — " + after("api-auth:"), "white")
    if low.startswith("api-fuzz:"):
        return ("api-fuzz  ", "cyan", "fuzzing JSON request bodies — " + after("api-fuzz:"), "white")
    if low.startswith("api-method:"):
        return ("api-method  ", "cyan", "probing undocumented HTTP methods — " + after("api-method:"), "white")

    # --- planning / app model ------------------------------------------------------------
    if low.startswith("orchestrator round"):
        return ("plan  ", "bold blue", "re-planning on newly-found surface — " + m.split(":", 1)[-1].strip(), "white")
    if low.startswith("orchestrator:"):
        return ("plan  ", "bold blue", "planning the attack — " + after("orchestrator:"), "white")
    if low.startswith("app-model:"):
        return ("model  ", "blue", "built a model of the app (entities, roles, workflows)", "white")

    # --- deterministic passes ------------------------------------------------------------
    if low.startswith("oast:"):
        r = after("oast:")
        if "confirmed by callback" in r:
            return ("oast 💥 ", "bold green", "blind vulnerability CONFIRMED by an out-of-band callback!", "white")
        if "callback host" in r:
            return ("oast  ", "cyan", "out-of-band listener is ready for blind-bug callbacks", "white")
        if "injected" in r:
            return ("oast  ", "cyan", "fired out-of-band payloads and waiting for a callback…", "white")
        return ("oast  ", "cyan", r, "white")
    if low.startswith("access-control:"):
        if "held" in low:
            return ("access-control  ", "cyan", "authz boundary held — no IDOR on tested endpoints", "white")
        return ("access-control  ", "cyan", "testing the authorization boundary across identities", "white")
    if low.startswith("role-matrix:"):
        return ("role-matrix  ", "cyan", "admin/privileged paths across roles — " + after("role-matrix:"), "white")
    if low.startswith("scenario:"):
        return ("scenario  ", "cyan", "business-logic scenarios — " + after("scenario:"), "white")
    if low.startswith("business-logic:"):
        return ("business-logic  ", "cyan", after("business-logic:"), "white")
    if low.startswith("client-side:"):
        return ("client-side  ", "cyan", after("client-side:"), "white")
    if low.startswith("csrf:"):
        return ("csrf  ", "cyan", after("csrf:"), "white")
    if low.startswith("cors:"):
        return ("cors  ", "cyan", after("cors:"), "white")
    if low.startswith("smuggle:"):
        return ("smuggle  ", "cyan", "request-smuggling check — " + after("smuggle:"), "white")
    if low.startswith("graphql-idor:"):
        return ("graphql-idor  ", "cyan", after("graphql-idor:"), "white")
    if low.startswith("graphql:"):
        return ("graphql  ", "cyan", after("graphql:"), "white")
    if low.startswith("boolean-sqli:") or low.startswith("blind-sqli:"):
        return ("sqli ✓ ", "bold green", "confirmed blind SQL injection deterministically "
                "— " + (after("boolean-sqli:") if "boolean-sqli:" in low else after("blind-sqli:")),
                "white")
    if low.startswith("sqli-extract:"):
        return ("sqli 💰 ", "bold green", "pulled a live value straight out of the database "
                "— " + after("sqli-extract:"), "white")
    if low.startswith("reflect-xss:"):
        r = after("reflect-xss:")
        if "EXECUTED" in r:
            return ("xss 💥 ", "bold green", "crafted a context-aware payload that EXECUTED "
                    "in the browser — " + r, "white")
        return ("reflect-xss  ", "cyan", "found input reflected un-escaped — " + r, "white")
    if low.startswith("sqlmap:"):
        return ("sqlmap  ", "cyan", after("sqlmap:"), "white")

    # --- validation / report -------------------------------------------------------------
    if "final validation sweep" in low:
        return ("validate  ", "bold white", "final pass — re-verifying every finding by replaying it", "white")
    if low.startswith("validation —"):
        return ("validate ✓ ", "bold white", after("validation —"), "white")
    if low.startswith("deepened:"):
        return ("deepen  ", "cyan", "dug deeper into " + after("deepened:"), "white")
    if low.startswith("collapse —") or low.startswith("dedupe —"):
        return ("report  ", "dim", "tidying the report (merging duplicate / per-page findings)", "dim")
    if "reporting phase" in low:
        return ("report  ", "bold white", "writing up the report", "white")
    if "assessment finished by agent" in low:
        return ("done  ", "green", "specialist wrapped up", "white")
    if "max turns reached" in low:
        return ("budget  ", "dim", "specialist hit its step budget — summarizing", "dim")
    if "[reauth]" in low:
        return ("re-auth  ", "yellow", "session expired mid-scan — logging back in", "white")
    if "[steer]" in low:
        return ("steer  ", "magenta", "operator steer: " + m.split("[steer]", 1)[-1].strip(), "white")
    return None


def narrate(type_: str, message: str) -> Text | None:
    """Map a raw (type, message) event to a human, talkative activity line (or None to skip).
    Deterministic — it only re-phrases facts already in the event; it never invents anything."""
    m = message or ""
    low = m.lower()
    if type_ == "think":
        return _line("💭 thinking  ", "bold cyan", m[:220], "dim")
    if type_ == "finding_validated":
        return _line("✓ confirmed  ", "bold green", m.replace("VALIDATED:", "").strip(), "bold white")
    if type_ == "finding":
        return _line("⚠ candidate  ", "yellow", m.replace("candidate filed:", "").strip(), "white")
    if type_ == "error":
        return _line("✗ error  ", "bold red", m, "red")
    if type_ == "tool_call":
        hm = _HTTP_RE.search(m)
        if hm:
            return _line("   → ", "cyan", f"{hm.group(1)} {_short(hm.group(2))}", "cyan")
        if m.startswith("exec_command"):
            return _line("   → ", "cyan", "run " + m[len("exec_command"):].strip(" :")[:80], "dim")
        return None
    if type_ == "tool_result":
        mm = re.search(r"->\s*(?:status=)?(\d{3})", m)
        if mm and mm.group(1)[0] in "45":          # surface only 4xx/5xx (the interesting ones)
            return _line("     ↳ ", "yellow", f"HTTP {mm.group(1)} — interesting", "yellow")
        return None
    if type_ == "status":
        sm = _SPEC_RE.search(m)
        if sm:
            cls = sm.group(1).lower()
            rest = sm.group(2).strip()
            title = _SPEC_TITLES.get(cls, cls.replace("_", " "))
            if "skipped" in rest:
                return None
            if "pre-probe auto-filed" in rest:
                body = "pre-probe already confirmed a finding — filing it"
            elif "browser scan auto-filed" in rest:
                body = "the browser confirmed an executing XSS"
            elif "reasoning over the app model" in rest:
                body = "reasoning over the app model for logic/authz flaws"
            elif "testing" in rest:
                body = "probing " + rest.split("testing", 1)[-1].strip()
            else:
                body = rest
            return _line(f"🔍 {title}  ", "bold yellow", body, "white")
        if re.search(r"turn \d+/\d+", low):
            return None                             # the turn counter lives in the status bar
        pretty = _pretty_status(m, low)
        if pretty:
            return _line(pretty[0], pretty[1], pretty[2], pretty[3])
        return _line("  ·  ", "dim", m[:160], "dim")   # any other status — still shown, dim
    if type_ == "log" and ("[reauth]" in low or "blocked duplicate" in low):
        return _line("  note  ", "dim", m, "dim")
    return None


def _line(tag: str, tag_style: str, body: str, body_style: str) -> Text:
    t = Text()
    t.append(tag, style=tag_style)
    t.append(body, style=body_style)
    return t


def _short(url: str) -> str:
    try:
        sp = urlsplit(url)
        return (sp.path or "/") + (("?" + sp.query) if sp.query else "")
    except Exception:
        return url[:80]


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


class RawLogScreen(ModalScreen):
    """The full raw tool-event stream (for debugging), behind the `L` key."""

    BINDINGS = [Binding("escape,q,l", "dismiss", "Close")]

    def __init__(self, lines: list[tuple[str, str]]) -> None:
        super().__init__()
        self._lines = lines

    def compose(self) -> ComposeResult:
        log = RichLog(id="detail", highlight=False, markup=False, wrap=False)
        yield log

    def on_mount(self) -> None:
        log = self.query_one("#detail", RichLog)
        for type_, message in self._lines[-1000:]:
            log.write(f"[{type_}] {message}"[:1000])

    def action_dismiss(self) -> None:
        self.app.pop_screen()


class AuthModal(ModalScreen):
    BINDINGS = [Binding("escape,enter,space", "done", "Done")]

    def __init__(self, novnc_url: str, done_event=None) -> None:
        super().__init__()
        self._url = novnc_url
        self._event = done_event

    def compose(self) -> ComposeResult:
        t = Text()
        t.append("Authentication needed\n\n", style="bold yellow")
        t.append("The scan hit a login / MFA challenge. Open this URL, complete the login\n"
                 "(password, OTP, push, CAPTCHA), then press Enter to continue:\n\n", style="white")
        t.append(self._url + "\n", style="cyan")
        yield VerticalScroll(Static(t), id="detail")

    def action_done(self) -> None:
        if self._event is not None:
            try:
                self._event.set()
            except Exception:
                pass
        self.app.pop_screen()


class ScanApp(App):
    CSS = """
    #status { height: 4; background: $panel; color: $text; padding: 0 1; border: round $accent; }
    #main { height: 1fr; }
    #activity { width: 2fr; border: round $accent; padding: 0 1; }
    #side { width: 1fr; }
    #findings { height: 42%; border: round $warning; }
    #target { height: 8; border: round $primary; padding: 0 1; }
    #surface { height: 1fr; border: round $surface; }
    #steer { dock: bottom; height: 3; border: round $accent; }
    #filter { display: none; }
    #detail { padding: 1 2; }
    """
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+q,ctrl+c", "quit", "Quit", show=False),
        Binding("d", "open", "Details", show=False),
        Binding("s", "sort", "Sort", show=False),
        Binding("v", "sev", "Severity", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("l", "rawlog", "Raw log", show=False),
    ]

    def __init__(self, assessment_id: str, target: str, model: str, scan_fn) -> None:
        super().__init__()
        self.aid = assessment_id
        self.target = target
        self.model = model
        self.scan_fn = scan_fn
        self._started = time.time()
        self._phase = "starting"
        self._last_feed_line = ""
        self._done = False
        self.result_status = "completed"
        self.result_summary = ""
        self.result_report = None
        self._filter = ""
        self._min_sev = -1
        self._sort_key = "sev"
        self._table_sig = None
        self._surface_sig = None
        self._steer: list[str] = []
        self._steer_lock = threading.Lock()
        self._raw: deque[tuple[str, str]] = deque(maxlen=2000)
        self._cur_class = ""
        self._cur_target = ""
        self._cur_method = ""
        self._cur_turn = ""

    def compose(self) -> ComposeResult:
        yield Static(id="status")
        with Horizontal(id="main"):
            yield RichLog(id="activity", highlight=False, markup=False, wrap=True, max_lines=1500)
            with Vertical(id="side"):
                yield DataTable(id="findings", zebra_stripes=True, cursor_type="row")
                yield Static(id="target")
                yield DataTable(id="surface", cursor_type="row")
        yield Input(placeholder="steer the scan — type a note, Enter to send", id="steer")
        yield Input(placeholder="filter findings — Enter to apply, empty to clear", id="filter")

    def on_mount(self) -> None:
        ft = self.query_one("#findings", DataTable)
        ft.add_columns("SEV", "STATUS", "FINDING")
        sf = self.query_one("#surface", DataTable)
        sf.add_columns("ENDPOINT", "PARAMS")
        self.query_one("#filter", Input).display = False
        ft.focus()
        self.set_interval(0.6, self._refresh)
        self._update_status()
        self._scan_thread = threading.Thread(target=self._scan, name="owlforge-scan", daemon=True)
        self._scan_thread.start()

    # ---- scan worker (daemon thread) -------------------------------------------------
    def _scan(self) -> None:
        from owlforge.engine.events import Emitter
        emit = Emitter(self.aid, dashboard=_TuiSink(self), persist=True)
        try:
            summary, report = self.scan_fn(emit, self.drain_steer)
            self.result_summary, self.result_report = summary, report
        except KeyboardInterrupt:
            self.result_status = "stopped"
        except Exception as e:
            self.result_status = "failed"
            try:
                self.call_from_thread(self._activity_error, f"{type(e).__name__}: {e}")
            except Exception:
                pass
        try:
            self.call_from_thread(self._scan_done)
        except Exception:
            pass

    # ---- UI-thread handlers ----------------------------------------------------------
    def on_scan_event(self, type_: str, message: str) -> None:
        self._raw.append((type_, message))
        # track current target/turn from the raw stream for the card
        if type_ == "tool_call":
            hm = _HTTP_RE.search(message or "")
            if hm:
                self._cur_method, self._cur_target = hm.group(1), hm.group(2)
        elif type_ == "status":
            sm = _SPEC_RE.search(message or "")
            if sm:
                self._cur_class = sm.group(1).lower()
            tm = re.search(r"turn (\d+/\d+)", message or "")
            if tm:
                self._cur_turn = tm.group(1)
            self._phase = _phase_of(message) or self._phase
        line = narrate(type_, message)
        if line is not None:
            _txt = line.plain
            if _txt != self._last_feed_line:          # collapse consecutive identical lines
                self._last_feed_line = _txt
                try:
                    self.query_one("#activity", RichLog).write(line)
                except Exception:
                    pass
        if type_ == "status":
            self._update_status()
            self._update_target()

    def _activity_error(self, msg: str) -> None:
        try:
            self.query_one("#activity", RichLog).write(_line("error  ", "bold red", msg, "red"))
        except Exception:
            pass

    # ---- findings ---------------------------------------------------------------------
    def _findings(self) -> list[dict]:
        try:
            from sqlmodel import select

            from owlforge.store.db import session
            from owlforge.store.models import Finding
            with session() as s:
                rows = s.exec(select(Finding).where(Finding.assessment_id == self.aid)).all()
            keep = [f for f in rows if f.status in ("validated", "candidate", "manual")]
            keep.sort(key=lambda f: (f.status != "validated", -_SEV_RANK.get((f.severity or "").lower(), 0)))
            return [{"id": f.id, "severity": f.severity or "info", "status": f.status,
                     "title": f.title or "", "endpoint": f.endpoint or "", "method": f.method,
                     "confidence": f.confidence, "technical_analysis": f.technical_analysis,
                     "proof_of_concept": f.proof_of_concept, "impact": f.impact,
                     "remediation": f.remediation, "validation_note": f.validation_note,
                     "evidence": f.evidence} for f in keep]
        except Exception:
            return []

    def _apply_view(self, rows: list[dict]) -> list[dict]:
        if self._min_sev >= 0:
            rows = [f for f in rows if _SEV_RANK.get(f["severity"].lower(), 0) >= self._min_sev]
        if self._filter:
            q = self._filter.lower()
            rows = [f for f in rows if q in f["title"].lower() or q in f["endpoint"].lower()
                    or q in f["severity"].lower() or q in f["status"].lower()]
        if self._sort_key == "status":
            rows.sort(key=lambda f: (f["status"] != "validated", -_SEV_RANK.get(f["severity"].lower(), 0)))
        elif self._sort_key == "title":
            rows.sort(key=lambda f: f["title"].lower())
        else:
            rows.sort(key=lambda f: (-_SEV_RANK.get(f["severity"].lower(), 0), f["status"] != "validated"))
        return rows

    def _surface(self) -> list[tuple[str, str]]:
        try:
            from sqlmodel import select

            from owlforge.store.db import session
            from owlforge.store.models import SurfaceItem
            with session() as s:
                rows = s.exec(select(SurfaceItem).where(SurfaceItem.assessment_id == self.aid)).all()
            out, seen = [], set()
            for r in rows:
                path = _short(r.url or "")
                key = ((r.method or "GET"), path)
                if key in seen:
                    continue
                seen.add(key)
                out.append((f"{r.method or 'GET'} {path}"[:46], ",".join(r.params or [])[:22]))
            return out
        except Exception:
            return []

    def _refresh(self) -> None:
        rows = self._apply_view(self._findings())
        self._row_cache = {f["id"]: f for f in rows}
        sig = (self._filter, self._min_sev, self._sort_key, tuple((f["id"], f["status"]) for f in rows))
        if sig != self._table_sig:
            self._table_sig = sig
            dt = self.query_one("#findings", DataTable)
            cur = dt.cursor_row
            dt.clear()
            for f in rows:
                sev = Text(f["severity"].upper()[:4], style=_SEV_STYLE.get(f["severity"].lower(), "white"))
                st = Text(f["status"][:5], style=_STATUS_STYLE.get(f["status"], "white"))
                dt.add_row(sev, st, (f["title"] or "")[:40], key=f["id"])
            try:
                if dt.row_count:
                    dt.move_cursor(row=min(max(cur, 0), dt.row_count - 1))
            except Exception:
                pass
        surf = self._surface()
        ssig = tuple(surf)
        if ssig != self._surface_sig:
            self._surface_sig = ssig
            sdt = self.query_one("#surface", DataTable)
            sdt.clear()
            for ep, params in surf[:200]:
                sdt.add_row(ep, params)
        self._update_status()
        self._update_target()

    def _update_status(self) -> None:
        el = int(time.time() - self._started)
        rows = getattr(self, "_row_cache", {})
        v = sum(1 for f in rows.values() if f["status"] == "validated")
        c = sum(1 for f in rows.values() if f["status"] in ("candidate", "manual"))
        try:
            stage = _STAGES.index("complete" if self._done else self._phase)
        except ValueError:
            stage = 1
        bar = "█" * (stage * 4) + "─" * ((len(_STAGES) - 1) * 4 - stage * 4)
        t = Text()
        t.append("owlforge  ", style="bold #fbbf24")
        t.append(f"{self.target}", style="white")
        t.append(f"   {self.model}\n", style="dim")
        t.append(f"phase {self._phase if not self._done else self.result_status}", style="bold #fcd34d")
        t.append(f"  {el // 60:02d}:{el % 60:02d}  ", style="dim")
        t.append(bar, style="#fbbf24")
        t.append(f"   {v} validated", style="bold green")
        t.append(f" / {c} candidate", style="yellow")
        t.append(f"   sort:{self._sort_key}", style="dim")
        if self._min_sev >= 0:
            t.append(" sev>=" + ["", "low", "medium", "high", "critical"][self._min_sev], style="dim")
        if self._filter:
            t.append(f" /{self._filter}", style="dim")
        if self._done:
            t.append("   [q to quit]", style="bold")
        try:
            self.query_one("#status", Static).update(t)
        except Exception:
            pass

    def _update_target(self) -> None:
        t = Text()
        t.append("current target\n", style="bold #9a7b4f")
        if self._cur_target:
            t.append(f"{self._cur_method} {_short(self._cur_target)}\n", style="#67e8f9")
            sp = urlsplit(self._cur_target)
            params = ",".join(dict.fromkeys(k for k in (sp.query or "").replace("&", "=").split("=")[::2] if k))
            t.append(f"params: {params or '-'}\n", style="dim")
        else:
            t.append("warming up…\n", style="dim")
        bits = []
        if self._cur_class:
            bits.append(f"class {_SPEC_TITLES.get(self._cur_class, self._cur_class)}")
        if self._cur_turn:
            bits.append(f"turn {self._cur_turn}")
        if bits:
            t.append("  ·  ".join(bits), style="dim")
        try:
            self.query_one("#target", Static).update(t)
        except Exception:
            pass

    def _scan_done(self) -> None:
        self._done = True
        self._refresh()
        self._phase = "complete"
        self._update_status()

    # ---- steering ---------------------------------------------------------------------
    def drain_steer(self) -> list[str]:
        with self._steer_lock:
            out = self._steer[:]
            self._steer.clear()
            return out

    # ---- actions ----------------------------------------------------------------------
    def action_sort(self) -> None:
        order = ["sev", "status", "title"]
        self._sort_key = order[(order.index(self._sort_key) + 1) % len(order)]
        self._table_sig = None
        self._refresh()

    def action_sev(self) -> None:
        steps = [-1, 1, 2, 3, 4]
        self._min_sev = steps[(steps.index(self._min_sev) + 1) % len(steps)]
        self._table_sig = None
        self._refresh()

    def action_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        inp.value = self._filter
        inp.display = True
        inp.focus()

    def action_rawlog(self) -> None:
        self.push_screen(RawLogScreen(list(self._raw)))

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

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "steer":
            txt = (event.value or "").strip()
            if txt:
                with self._steer_lock:
                    self._steer.append(txt)
                self.query_one("#activity", RichLog).write(_line("steer  ", "bold magenta", txt, "white"))
            event.input.value = ""
            return
        self._filter = (event.value or "").strip()
        inp = self.query_one("#filter", Input)
        inp.display = False
        self.query_one("#findings", DataTable).focus()
        self._table_sig = None
        self._refresh()

    def pause_for_auth(self, novnc_url: str, done_event=None) -> None:
        self.push_screen(AuthModal(novnc_url, done_event))


def run_scan_tui(assessment_id: str, target: str, model: str, scan_fn):
    """Run the scan inside the interactive dashboard. scan_fn(emit, steer_fn) ->
    (summary, report). Returns (status, summary, report_path) after the user quits."""
    app = ScanApp(assessment_id, target, model, scan_fn)
    app.run()
    return app.result_status, app.result_summary, app.result_report
