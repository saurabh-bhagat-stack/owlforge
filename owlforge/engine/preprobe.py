"""Deterministic pre-probe — gate the LLM.

Before spending a model on a specialist, mechanically test each target. Only
signal-positive targets advance to the (expensive) specialist, and the probe tells it
exactly what fired. Machines do detection; the model does reasoning/exploitation. Big
precision + compute win — matters most for weak/local drivers.
"""

from __future__ import annotations

import secrets as _secrets

from owlforge.engine.classify import PATH, RCE, SQLI, SSRF, SSTI, XSS

# classes with a cheap, sound single-request signal. access_control / csrf need a
# differential and are NOT gated here (they pass through to the specialist/validator).
GATEABLE = {SQLI, XSS, PATH, SSRF, SSTI, RCE}


def _http(sandbox, method, url, params, headers):
    try:
        return sandbox.http_request(method or "GET", url, params=params, headers=headers or None)
    except Exception:
        return {}


def probe(cls: str, target: dict, sandbox, session_headers: dict | None = None) -> tuple[bool, str]:
    """Return (signal, note). A True signal means the class is worth a specialist on
    this target; note describes what fired (fed to the specialist)."""
    url = target["url"]
    p = target.get("param")
    method = target.get("method", "GET")
    h = session_headers or None
    if sandbox is None or p is None:
        return True, ""   # can't param-probe (endpoint-level) -> don't gate, let the specialist look

    if cls == SQLI:
        base = _http(sandbox, method, url, {p: "1"}, h)
        inj = _http(sandbox, method, url, {p: "1'"}, h)
        bs, is_ = int(base.get("status") or 0), int(inj.get("status") or 0)
        if bs and is_ >= 500 and bs < 500:
            return True, f"{p}: single-quote -> HTTP {is_} vs baseline {bs} (error-based SQLi signal)"
        bl, il = len(base.get("body") or ""), len(inj.get("body") or "")
        if bl and abs(bl - il) / max(bl, il) > 0.3:
            return True, f"{p}: single-quote changed response size {bl}->{il}"
        return False, ""

    if cls == XSS:
        m = "owlx" + _secrets.token_hex(3)
        r = _http(sandbox, method, url, {p: f"<{m}>"}, h)
        if f"<{m}>" in (r.get("body") or ""):
            return True, f"{p}: raw marker <{m}> reflected unencoded (candidate XSS sink)"
        return False, ""

    if cls == PATH:
        r = _http(sandbox, method, url, {p: "../../../../etc/passwd"}, h)
        if "root:x:0:0" in (r.get("body") or ""):
            return True, f"{p}: /etc/passwd contents returned (path traversal)"
        return False, ""

    if cls == SSTI:
        # unique product so a coincidental "49" can't false-positive
        for payload in ("{{1337*1337}}", "${1337*1337}", "<%=1337*1337%>", "#{1337*1337}"):
            r = _http(sandbox, method, url, {p: payload}, h)
            if "1787569" in (r.get("body") or ""):
                return True, f"{p}: template evaluated {payload} -> 1787569 (SSTI)"
        return False, ""

    if cls == RCE:
        for payload in ("1;id", "1|id", "$(id)", "1&&id", "`id`"):
            r = _http(sandbox, method, url, {p: payload}, h)
            body = r.get("body") or ""
            if "uid=" in body and "gid=" in body:
                return True, f"{p}: command injection {payload} -> id output (uid=/gid=)"
        return False, ""

    if cls == SSRF:
        mark = f"http://owl-{_secrets.token_hex(3)}.probe/"
        r = _http(sandbox, method, url, {p: mark}, h)
        hdrs = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        if mark in hdrs.get("location", "") or mark in (r.get("body") or ""):
            return True, f"{p}: attacker URL reflected in redirect/body (SSRF/open-redirect)"
        return False, ""

    return True, ""


def filter_targets(cls: str, targets: list[dict], sandbox, session_headers: dict | None = None
                   ) -> tuple[list[dict], list[str]]:
    """For a gateable class, return (targets_with_signal, probe_notes). Non-gateable
    classes pass through unchanged."""
    if cls not in GATEABLE or sandbox is None:
        return targets, []
    kept, notes = [], []
    for t in targets:
        sig, note = probe(cls, t, sandbox, session_headers)
        if sig:
            kept.append(t)
            if note:
                notes.append(note)
    return kept, notes
