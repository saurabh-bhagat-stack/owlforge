"""Shared narration layer: turn a raw (type, message) event into a human, first-person activity
line, in a renderer-agnostic form so the plain stream, the Textual TUI and the web console all tell
the SAME story. Deterministic — it only re-phrases facts already in the event, never invents.

A NarratedLine carries a tag, a body, Rich styles (for the terminal) and a coarse `kind`/`hygiene`
flag (for web CSS, filtering and grouping). `is_hygiene` marks the passive header/cookie/version
findings so renderers can fold them instead of burying real findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_STAGES = ["starting", "recon", "hunt", "deterministic passes", "validation", "reporting",
           "complete"]
_PHASES = (
    ("reporting", "reporting"), ("collapse", "reporting"), ("dedupe", "reporting"),
    ("final validation", "validation"), ("validation", "validation"), ("deepen", "validation"),
    ("oast", "deterministic passes"), ("access-control", "deterministic passes"),
    ("bola", "deterministic passes"),
    ("csrf", "deterministic passes"), ("cors", "deterministic passes"),
    ("smuggle", "deterministic passes"), ("graphql", "deterministic passes"),
    ("session", "deterministic passes"), ("client-side", "deterministic passes"),
    ("business-logic", "deterministic passes"),
    ("orchestrator", "hunt"), ("[specialist:", "hunt"), ("pre-probe", "hunt"), ("recon", "recon"),
)

_SPEC_TITLES = {"sqli": "SQL injection", "xss": "XSS", "access_control": "access-control",
                "ssrf_redirect": "SSRF/redirect", "rce": "RCE", "ssti": "template injection",
                "xxe": "XXE", "path_traversal": "path traversal", "open_redirect": "open redirect",
                "csrf": "CSRF", "nosql": "NoSQL", "graphql": "GraphQL", "crlf": "CRLF",
                "file_upload": "file upload", "deserialization": "deserialization"}
_SPEC_RE = re.compile(r"\[specialist:([a-z_]+)\]\s*(.*)", re.I)
_HTTP_RE = re.compile(r"http_request\s+([A-Z]+)\s+(\S+)")

_HYGIENE_RE = re.compile(
    r"missing (content-security-policy|x-content-type|strict-transport|x-frame|referrer|"
    r"permissions-policy)|x-content-type-options|clickjacking|x-frame-options|"
    r"version disclosure|server version|cookie without|missing .*header|cache-control|"
    r"content-type-options|frame-ancestors", re.I)


def phase_of(message: str) -> str | None:
    low = (message or "").lower()
    for key, label in _PHASES:
        if key in low:
            return label
    return None


def is_hygiene(message: str) -> bool:
    """True for passive security-hygiene findings (missing headers, cookie flags, version banner)."""
    return bool(_HYGIENE_RE.search(message or ""))


def _short(url: str) -> str:
    try:
        sp = urlsplit(url)
        return (sp.path or "/") + (("?" + sp.query) if sp.query else "")
    except Exception:
        return url[:80]


@dataclass
class NarratedLine:
    tag: str
    body: str
    tag_style: str = "white"
    body_style: str = "white"
    kind: str = "activity"        # activity | think | tool | http | finding
    hygiene: bool = False


def _nl(tag, tag_style, body, body_style, kind="activity", hygiene=False) -> NarratedLine:
    return NarratedLine(tag=tag, body=body, tag_style=tag_style, body_style=body_style,
                        kind=kind, hygiene=hygiene)


def _pretty_status(m: str, low: str):
    def after(key: str) -> str:
        return m.split(key, 1)[-1].strip() if key in low else m.strip()

    if low.startswith("unauth recon"):
        return ("recon  ", "bold cyan", "sizing up the app as an anonymous visitor first", "white")
    if "recon: crawled" in low:
        return ("recon  ", "bold cyan", "crawled the site — " + m.split("crawled", 1)[-1].strip(),
                "white")
    if low.startswith("content discovery"):
        return ("recon  ", "cyan", "brute-forced hidden paths — found " + after("content discovery:"),
                "white")
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
        return ("secrets  ", "cyan",
                "scanning pages, JS & files for leaked secrets and credentials", "white")
    if "browser-logged-in" in low or ("harvested" in low and "credential" in low):
        cred = re.search(r"\(([^)]+)\)", m)
        creds = cred.group(1) if cred else "an account shown on the page"
        return ("auth OK ", "bold green",
                f"logged in with credentials found on the page — {creds}", "white")
    if low.startswith("api-surface:"):
        return ("api-surface  ", "bold cyan",
                "mined the JS bundle for the hidden API — " + after("api-surface:"), "white")
    if low.startswith("auth:"):
        tag = "auth OK " if "operating with" in low else (
            "auth !! " if "unauthenticated" in low else "auth  ")
        ts = "bold green" if "operating with" in low else (
            "bold red" if "unauthenticated" in low else "bold green")
        return (tag, ts, after("auth:"), "white")
    if low.startswith("recon-summary:"):
        return ("recon OK ", "bold cyan", "recon complete — " + after("recon-summary:"), "white")
    if low.startswith("surface:"):
        return ("surface  ", "bold green", after("surface:"), "white")
    if "auth recon" in low and "re-mapping" in low:
        return ("recon  ", "cyan", "re-mapping the surface while logged in", "white")

    if low.startswith("seed:"):
        r = after("seed:")
        if "logged in" in r:
            r = "registered a throwaway account and logged in (two-step)"
        elif "registered a throwaway" in r or ("registered (" in r and "session" in r):
            r = "registered a throwaway account to test with"
        elif "created a test object" in r:
            r = "created a test object to attack — " + r.split("->", 1)[-1].strip()
        elif "could not establish" in r:
            r = "registered, but could not get a session (login step needed)"
        elif "provisioned a second" in r:
            r = "made a 2nd account so we can test one user against another (IDOR)"
        return ("seed  ", "magenta", r, "white")

    if low.startswith("nuclei:"):
        return ("nuclei  ", "cyan", "ran the CVE/misconfig template set — " + after("nuclei:"),
                "white")
    if low.startswith("spec:"):
        return ("api-spec  ", "cyan", "loaded " + after("spec:") + " from the API description",
                "white")
    if low.startswith("api-auth:"):
        return ("api-auth  ", "cyan",
                "checking spec-protected ops for missing auth — " + after("api-auth:"), "white")
    if low.startswith("api-fuzz:"):
        return ("api-fuzz  ", "cyan", "fuzzing JSON request bodies — " + after("api-fuzz:"), "white")
    if low.startswith("api-method:"):
        return ("api-method  ", "cyan", "probing undocumented HTTP methods — " + after("api-method:"),
                "white")

    if low.startswith("orchestrator round"):
        return ("plan  ", "bold blue", "re-planning on newly-found surface — "
                + m.split(":", 1)[-1].strip(), "white")
    if low.startswith("orchestrator:"):
        return ("plan  ", "bold blue", "planning the attack — " + after("orchestrator:"), "white")
    if low.startswith("app-model:"):
        return ("model  ", "blue", "built a model of the app (entities, roles, workflows)", "white")

    if low.startswith("oast:"):
        r = after("oast:")
        if "confirmed by callback" in r:
            return ("oast !! ", "bold green",
                    "blind vulnerability CONFIRMED by an out-of-band callback!", "white")
        if "callback host" in r:
            return ("oast  ", "cyan", "out-of-band listener is ready for blind-bug callbacks", "white")
        if "injected" in r:
            return ("oast  ", "cyan", "fired out-of-band payloads and waiting for a callback…",
                    "white")
        return ("oast  ", "cyan", r, "white")
    if low.startswith("access-control:"):
        if "held" in low:
            return ("access-control  ", "cyan", "authz boundary held — no IDOR on tested endpoints",
                    "white")
        return ("access-control  ", "cyan", "testing the authorization boundary across identities",
                "white")
    if low.startswith("bola:"):
        return ("bola  ", "cyan", "harvesting object IDs and replaying them across users — "
                + after("bola:"), "white")
    if low.startswith("role-matrix:"):
        return ("role-matrix  ", "cyan", "admin/privileged paths across roles — "
                + after("role-matrix:"), "white")
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
        return ("sqli OK ", "bold green", "confirmed blind SQL injection deterministically — "
                + (after("boolean-sqli:") if "boolean-sqli:" in low else after("blind-sqli:")),
                "white")
    if low.startswith("sqli-extract:"):
        return ("sqli $$ ", "bold green",
                "pulled a live value straight out of the database — " + after("sqli-extract:"),
                "white")
    if low.startswith("reflect-xss:"):
        r = after("reflect-xss:")
        if "EXECUTED" in r:
            return ("xss !! ", "bold green",
                    "crafted a context-aware payload that EXECUTED in the browser — " + r, "white")
        return ("reflect-xss  ", "cyan", "found input reflected un-escaped — " + r, "white")
    if low.startswith("sqlmap:"):
        return ("sqlmap  ", "cyan", after("sqlmap:"), "white")

    if "final validation sweep" in low:
        return ("validate  ", "bold white", "final pass — re-verifying every finding by replaying it",
                "white")
    if low.startswith("validation —"):
        return ("validate OK ", "bold white", after("validation —"), "white")
    if low.startswith("deepened:"):
        return ("deepen  ", "cyan", "dug deeper into " + after("deepened:"), "white")
    if low.startswith("collapse —") or low.startswith("dedupe —"):
        return ("report  ", "dim", "tidying the report (merging duplicate / per-page findings)",
                "dim")
    if "reporting phase" in low:
        return ("report  ", "bold white", "writing up the report", "white")
    if "assessment finished by agent" in low:
        return ("done  ", "green", "specialist wrapped up", "white")
    if "max turns reached" in low:
        return ("budget  ", "dim", "specialist hit its step budget — summarizing", "dim")
    if "[reauth]" in low:
        return ("re-auth  ", "yellow", "session expired mid-scan — logging back in", "white")
    if "[steer]" in low:
        return ("steer  ", "magenta", "operator steer: " + m.split("[steer]", 1)[-1].strip(),
                "white")
    return None


def narrate(type_: str, message: str, data: dict | None = None):
    """Map a raw (type, message) event to a NarratedLine, or None to skip it entirely."""
    m = message or ""
    low = m.lower()
    if type_ == "think":
        return _nl("thinking  ", "bold cyan", m[:220], "dim", kind="think")
    if type_ == "finding_validated":
        body = m.replace("VALIDATED:", "").strip()
        return _nl("confirmed  ", "bold green", body, "bold white", kind="finding",
                   hygiene=is_hygiene(body))
    if type_ == "finding":
        body = m.replace("candidate filed:", "").strip()
        return _nl("candidate  ", "yellow", body, "white", kind="finding", hygiene=is_hygiene(body))
    if type_ == "error":
        return _nl("error  ", "bold red", m, "red", kind="activity")
    if type_ == "finish":
        return _nl("summary  ", "bold green", m.strip()[:400], "white", kind="activity")
    if type_ == "note":
        return _nl("note  ", "magenta", m[:240], "white", kind="activity")
    if type_ == "tool_call":
        hm = _HTTP_RE.search(m)
        if hm:
            return _nl("   -> ", "cyan", f"{hm.group(1)} {_short(hm.group(2))}", "cyan", kind="http")
        if m.startswith("exec_command"):
            return _nl("   -> ", "cyan", "run " + m[len("exec_command"):].strip(" :")[:80], "dim",
                       kind="tool")
        return None
    if type_ == "tool_result":
        mm = re.search(r"->\s*(?:status=)?(\d{3})", m)
        if mm and mm.group(1)[0] in "45":
            return _nl("     -> ", "yellow", f"HTTP {mm.group(1)} — interesting", "yellow",
                       kind="http")
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
            return _nl(f"{title}  ", "bold yellow", body, "white", kind="activity")
        if re.search(r"turn \d+/\d+", low):
            return None
        pretty = _pretty_status(m, low)
        if pretty:
            return _nl(pretty[0], pretty[1], pretty[2], pretty[3], kind="activity")
        return _nl("  ·  ", "dim", m[:160], "dim", kind="activity")
    if type_ == "log" and ("[reauth]" in low or "blocked duplicate" in low):
        return _nl("  note  ", "dim", m, "dim", kind="activity")
    return None


class Transcript:
    """Append the narrated run to transcript.md in the assessment dir, so the operator can copy
    anything (the TUI can't be selected). Best-effort; never breaks the scan."""
    def __init__(self, assessment_id: str) -> None:
        self.path = None
        try:
            from owlforge.config import assessments_dir
            d = assessments_dir() / assessment_id
            d.mkdir(parents=True, exist_ok=True)
            self.path = d / "transcript.md"
            with open(self.path, "w") as fh:
                fh.write(f"# owlforge run transcript — {assessment_id}\n\n")
        except Exception:
            self.path = None
        self._phase = None

    def write(self, line: NarratedLine, phase: str | None = None) -> None:
        if not self.path:
            return
        try:
            with open(self.path, "a") as fh:
                if phase and phase != self._phase:
                    self._phase = phase
                    fh.write(f"\n## {phase}\n\n")
                tag = line.tag.strip()
                fh.write(f"- **{tag}** {line.body}\n" if tag else f"- {line.body}\n")
        except Exception:
            pass
