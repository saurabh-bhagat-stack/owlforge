"""Evidence-gated validation.

A candidate finding is only promoted to `validated` if its own proof reproduces:
we re-run the agent-supplied `repro_command` in the sandbox and require the
`success_signal` to appear in the output (or, if no signal was given, a zero exit).
This is the core owlforge principle — a finding is confirmed by re-test, not by the
model's assertion. Findings with no repro stay `candidate` (manual validation needed).
"""

from __future__ import annotations

import asyncio
import html
import secrets
from datetime import UTC

from sqlmodel import select

from owlforge.engine.events import Emitter
from owlforge.sandbox.client import SandboxClient
from owlforge.store.db import session
from owlforge.store.models import Finding

_ACCESS_KEYWORDS = ("idor", "access control", "access-control", "authorization",
                    "broken access", "bola", "privilege escalation", "unauthor")


def _needs_differential(title: str) -> bool:
    """Access-control/IDOR can't be confirmed by a single successful request — a 200 with
    content is not proof of a boundary violation. These need differential testing
    (authorized vs unauthorized, or two accounts), which the signal gate cannot do."""
    t = (title or "").lower()
    return any(k in t for k in _ACCESS_KEYWORDS)


_XSS_KEYWORDS = ("xss", "cross-site scripting", "cross site scripting", "script injection")


def _is_xss(title: str) -> bool:
    t = (title or "").lower()
    return any(k in t for k in _XSS_KEYWORDS)


async def _browser_confirm_xss(sandbox: SandboxClient, rurl: str, rparams: dict) -> tuple[bool, bool, str]:
    """Confirm XSS by EXECUTION in real Chromium (via agentd /xss_check). Injects a
    sentinel payload that sets window.__owl_xss=token; returns (ran, executed, via).
    ran=False only if the sandbox image has no xss_check (older build) — then the
    caller falls back to the HTTP-text gate."""
    if not hasattr(sandbox, "xss_check"):
        return (False, False, "")
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    token = "owlxss" + secrets.token_hex(6)
    payloads = [
        f"<script>window.__owl_xss='{token}'</script>",
        f"\"><script>window.__owl_xss='{token}'</script>",
        f"<img src=x onerror=\"window.__owl_xss='{token}'\">",
        f"'><img src=x onerror=window.__owl_xss='{token}'>",
    ]
    params = {k: str(v) for k, v in (rparams or {}).items()}
    # prefer params the agent already fuzzed (payload-looking values), else all params
    hints = ("<", ">", "script", "onerror", "alert", '"', "'")
    cand = [k for k, v in params.items() if any(h in v for h in hints)] or list(params.keys())
    cand = cand[:2] or [None]

    sp = urlsplit(rurl)
    base_q = dict(parse_qsl(sp.query))
    base_q.update(params)
    for pname in cand:
        for pl in payloads:
            q = dict(base_q)
            q[pname if pname is not None else "q"] = pl
            url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), sp.fragment))
            try:
                res = await asyncio.to_thread(sandbox.xss_check, url, token)
            except Exception:
                continue
            if res.get("executed"):
                return (True, True, res.get("via", "browser"))
    return (True, False, "")


async def validate_findings(
    *, assessment_id: str, sandbox: SandboxClient | None, emit: Emitter,
    session_headers: dict | None = None,
) -> dict[str, int]:
    with session() as s:
        rows = s.exec(
            select(Finding).where(
                Finding.assessment_id == assessment_id, Finding.status == "candidate"
            )
        ).all()
        items = [(f.id, f.repro_command, f.success_signal, f.title,
                  f.repro_method, f.repro_url, dict(f.repro_params or {}), f.repro_body) for f in rows]

    counts = {"validated": 0, "rejected": 0, "manual": 0}
    for fid, repro, signal, title, rmethod, rurl, rparams, rbody in items:
        if _needs_differential(title):
            if sandbox is not None and session_headers and rurl.strip():
                verdict, note = await _differential_access(
                    sandbox, rmethod, rurl, rparams, rbody, session_headers)
                if verdict == "validated":
                    _set(fid, "validated", confidence="high", note=note)
                    counts["validated"] += 1
                    emit("finding_validated", f"VALIDATED: {title}")
                    continue
                if verdict == "rejected":
                    _set(fid, "false_positive", note=note)
                    counts["rejected"] += 1
                    emit("finding_rejected", f"rejected ({note}): {title}")
                    continue
                _set(fid, "candidate", note=f"access-control needs manual review — {note}")
                counts["manual"] += 1
                emit("log", f"access-control inconclusive (manual): {title}")
                continue
            _set(fid, "candidate", note=("access-control/IDOR needs differential testing "
                 "(authorized vs unauthorized / two accounts) — no session available to auto-test"))
            counts["manual"] += 1
            emit("log", f"access-control finding kept as candidate (needs differential): {title}")
            continue
        if not (rurl.strip() or repro.strip()):
            _set(fid, "candidate", note="no repro supplied — manual validation required")
            counts["manual"] += 1
            emit("log", f"manual-review (no repro): {title}")
            continue
        if sandbox is None:
            _set(fid, "candidate", note="no sandbox available to validate")
            counts["manual"] += 1
            continue
        if _is_xss(title) and rurl.strip():
            ran, executed, via = await _browser_confirm_xss(sandbox, rurl, rparams)
            if ran and executed:
                _set(fid, "validated", confidence="high",
                     note=f"reproduced: XSS EXECUTED in real browser — {via}")
                counts["validated"] += 1
                emit("finding_validated", f"VALIDATED: {title}")
                continue
            if ran and not executed:
                _set(fid, "false_positive",
                     note="not reproduced: payload did not execute in a real browser "
                          "(escaped output or non-executing sink)")
                counts["rejected"] += 1
                emit("finding_rejected", f"rejected (no browser execution): {title}")
                continue
            # ran is False (older image without xss_check) -> fall through to HTTP-text gate
        try:
            if rurl.strip():
                from owlforge.tools.builtin import _normalize_params
                params = _normalize_params(rparams) if rparams else None
                d = await asyncio.to_thread(
                    sandbox.http_request, rmethod or "GET", rurl, params=params, body=(rbody or None)
                )
                out = f"{d.get('status', '')}\n{d.get('headers', '')}\n{d.get('body', '') or ''}".lower()
            else:
                r = await asyncio.to_thread(sandbox.exec, repro, timeout_ms=60_000)
                out = f"{r.stdout}\n{r.stderr}".lower()
            sig = signal.strip()
            if not sig:
                reproduced, reason = (r.exit_code == 0), "exit 0 (no signal supplied)"
            else:
                enc = html.escape(sig)
                if sig.lower() in out:
                    reproduced, reason = True, "signal reflected raw"
                elif enc.lower() != sig.lower() and enc.lower() in out:
                    # The marker is present ONLY in HTML-encoded form -> the input was
                    # escaped on output -> a reflection, not an executable injection.
                    reproduced, reason = False, "signal only present HTML-encoded (escaped) — not exploitable"
                else:
                    reproduced, reason = False, "signal not found in output"
        except Exception as e:
            _set(fid, "candidate", note=f"validation error: {type(e).__name__}: {e}")
            counts["manual"] += 1
            continue
        if reproduced:
            _set(fid, "validated", confidence="high", note=f"reproduced: {reason}")
            counts["validated"] += 1
            emit("finding_validated", f"VALIDATED: {title}")
        else:
            _set(fid, "false_positive", note=f"not reproduced: {reason}")
            counts["rejected"] += 1
            emit("finding_rejected", f"rejected ({reason}): {title}")
    return counts


def _looks_like_login(body: str) -> bool:
    b = (body or "").lower()
    return ("password" in b and ("login" in b or "sign in" in b or "<form" in b)) or "please log in" in b


def _similar(a: str, b: str) -> bool:
    """Two response bodies are 'equivalent' if their lengths are within 10% — a cheap
    proxy for 'the anonymous request got the same protected resource'."""
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return False
    return min(la, lb) / max(la, lb) >= 0.9


async def _differential_access(
    sandbox: SandboxClient, method: str, url: str, params: dict, body: str, session_headers: dict
) -> tuple[str, str]:
    """Confirm broken access control by DIFFERENTIAL test: fetch the resource both
    authenticated and anonymously. Returns (verdict, note) where verdict is
    'validated' (reachable anonymously), 'rejected' (boundary enforced), or
    'inconclusive'. Sound because it directly probes the authz boundary rather than
    trusting a single 200."""
    from owlforge.tools.builtin import _normalize_params

    norm = _normalize_params(params) if params else None
    m = method or "GET"
    authed = await asyncio.to_thread(
        sandbox.http_request, m, url, headers=session_headers, params=norm, body=(body or None))
    anon = await asyncio.to_thread(
        sandbox.http_request, m, url, headers={}, params=norm, body=(body or None))
    a_status, a_body = int(authed.get("status") or 0), (authed.get("body") or "")
    n_status, n_body = int(anon.get("status") or 0), (anon.get("body") or "")

    if a_status != 200 or len(a_body) < 50:
        return ("inconclusive", f"authenticated request is not a usable resource (status {a_status})")
    if n_status in (401, 403) or 300 <= n_status < 400 or len(n_body) < 50:
        return ("rejected", f"boundary enforced: anonymous status {n_status} vs authenticated {a_status}")
    if _looks_like_login(n_body):
        return ("rejected", "boundary enforced: anonymous request returned a login page")
    if n_status == 200 and _similar(a_body, n_body):
        return ("validated",
                f"broken access control: protected resource reachable anonymously "
                f"(authenticated {a_status} == anonymous {n_status}, equivalent content)")
    return ("inconclusive", f"anonymous status {n_status}; content differs — manual review")


def _set(finding_id: str, status: str, *, confidence: str | None = None, note: str = "") -> None:
    from datetime import datetime

    with session() as s:
        f = s.get(Finding, finding_id)
        if not f:
            return
        f.status = status
        if confidence:
            f.confidence = confidence
        if note:
            f.validation_note = note
        f.updated_at = datetime.now(UTC)
        s.add(f)
        s.commit()


_CLASS_HINTS = (
    ("sqli", ("sql injection", "sqli")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("access_control", ("idor", "access control", "access-control", "broken access", "bola", "privilege")),
    ("ssrf", ("ssrf", "server-side request")),
    ("open_redirect", ("open redirect", "redirect")),
    ("path_traversal", ("path traversal", "lfi", "local file", "directory traversal")),
    ("rce", ("rce", "remote code", "command injection", "os command")),
    ("ssti", ("ssti", "template injection")),
    ("csrf", ("csrf", "cross-site request")),
    ("xxe", ("xxe", "xml external")),
    ("cors", ("cors",)),
    ("info_disclosure", ("information disclosure", "info disclosure", "secret", "api key", "token exposed")),
    ("file_upload", ("file upload", "unrestricted upload", "webshell")),
)


def _class_hint(title: str) -> str:
    t = (title or "").lower()
    for name, keys in _CLASS_HINTS:
        if any(k in t for k in keys):
            return name
    return "other"


_STATUS_RANK = {"validated": 3, "candidate": 2, "false_positive": 1, "duplicate": 0}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def dedupe_findings(assessment_id: str, emit: Emitter | None = None) -> int:
    """Collapse overlapping findings (same class + endpoint + method + params) to the
    single best instance (validated > candidate > false_positive, then higher severity);
    the rest are marked status='duplicate' so the report shows each issue once. Returns
    how many were collapsed."""
    with session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
        groups: dict[tuple, list[Finding]] = {}
        for f in rows:
            if f.status == "duplicate":
                continue
            key = (_class_hint(f.title), (f.endpoint or f.repro_url or "").rstrip("/"),
                   (f.method or f.repro_method or "GET").upper(),
                   tuple(sorted((f.repro_params or {}).keys())))
            groups.setdefault(key, []).append(f)

        collapsed = 0
        for group in groups.values():
            if len(group) < 2:
                continue
            group.sort(key=lambda f: (_STATUS_RANK.get(f.status, 0),
                                      _SEV_RANK.get((f.severity or "").lower(), 0)), reverse=True)
            for dup in group[1:]:
                dup.status = "duplicate"
                dup.validation_note = (dup.validation_note or "") + " [deduped: see " + group[0].id + "]"
                s.add(dup)
                collapsed += 1
        if collapsed:
            s.commit()
    if collapsed and emit is not None:
        emit("status", f"dedupe — collapsed {collapsed} duplicate finding(s)")
    return collapsed

