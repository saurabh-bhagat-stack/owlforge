"""Stored / second-order injection pass.

Reflected tests miss stored XSS and second-order SQLi because the payload lands in one
request and fires in a LATER, different response. This pass submits a unique marker +
payload to each writable form, then re-crawls the site and looks for the marker coming
back raw elsewhere — and confirms stored XSS by executing it in the browser.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from urllib.parse import urlencode


def stored_scan(assessment_id: str, inventory: list[dict], sandbox,
                session_headers: dict | None = None,
                log: Callable[[str], None] = lambda m: None) -> int:
    """Submit a stored-XSS marker to writable forms, re-crawl, and file (and browser-
    confirm) any stored injection. Returns findings filed."""
    if sandbox is None:
        return 0
    from owlforge.engine.csrf import extract_token
    from owlforge.store.db import session
    from owlforge.store.models import Finding

    token = "owlstored" + secrets.token_hex(4)
    payload = f'{token}"><img src=x onerror="window.__owl_xss=\'{token}\'">'
    hdrs = {**(session_headers or {}), "Content-Type": "application/x-www-form-urlencoded"}

    forms = [it for it in inventory
             if it.get("method", "GET").upper() == "POST" and it.get("source") == "form"
             and it.get("params")]
    submitted = 0
    for f in forms[:8]:
        params: dict[str, str] = {}
        for p in f["params"]:
            lp = p.lower()
            if lp in ("password", "email", "username", "user"):
                params[p] = "owl@example.com" if "email" in lp else "owltester"
            elif lp in ("csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken",
                        "authenticity_token", "__requestverificationtoken", "_token"):
                params[p] = ""  # filled below from a fresh token
            else:
                params[p] = payload
        # rotation-safe CSRF: fetch the form page, read the current token
        try:
            page = sandbox.http_request("GET", f["url"], headers=session_headers or None)
            tok = extract_token(page.get("body") or "")
            if tok:
                params[tok[0]] = tok[1]
        except Exception:
            pass
        try:
            sandbox.http_request("POST", f["url"], headers=hdrs, body=urlencode(params))
            submitted += 1
        except Exception:
            continue
    if not submitted:
        return 0
    log(f"stored: submitted marker to {submitted} form(s), re-crawling for reflection")

    pages = []
    for it in inventory:
        u = it.get("url", "")
        if it.get("method", "GET").upper() == "GET" and u not in pages:
            pages.append(u)
    pages = pages[:15]

    filed = 0
    for u in pages:
        try:
            r = sandbox.http_request("GET", u, headers=session_headers or None)
        except Exception:
            continue
        body = r.get("body") or ""
        if token not in body:
            continue
        raw_payload_present = 'onerror="window.__owl_xss' in body or f'{token}">' in body
        executed = False
        via = ""
        if raw_payload_present and hasattr(sandbox, "xss_check"):
            try:
                res = sandbox.xss_check(u, token, headers=session_headers or None)
                executed, via = bool(res.get("executed")), res.get("via", "")
            except Exception:
                pass
        with session() as s:
            if executed:
                s.add(Finding(
                    id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
                    title=f"Stored XSS (fires on {u})", severity="high", endpoint=u, method="GET",
                    technical_analysis=f"A payload submitted to a form is stored and EXECUTES when {u} "
                                       "is rendered (second-order/stored XSS).",
                    proof_of_concept=f"payload {payload} -> executes at {u} ({via})",
                    evidence=f"window.__owl_xss == {token} on {u}",
                    impact="Stored XSS runs in every victim's browser that views the page.",
                    remediation="Context-encode on output and sanitize stored input.",
                    status="validated", confidence="high",
                    validation_note=f"stored XSS executed in browser — {via}"))
                log(f"stored: VALIDATED stored XSS firing on {u}")
            else:
                kind = "raw (likely injectable)" if raw_payload_present else "encoded"
                s.add(Finding(
                    id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
                    title=f"Stored/second-order reflection on {u}", severity="medium", endpoint=u,
                    method="GET", technical_analysis=f"Input submitted elsewhere is reflected ({kind}) at "
                    f"{u} — second-order sink; review for stored XSS / second-order injection.",
                    proof_of_concept=f"marker {token} submitted to a form appears on {u} ({kind})",
                    evidence=token, status="candidate", confidence="medium",
                    validation_note="stored/second-order reflection (manual confirm)"))
            s.commit()
            filed += 1
    log(f"stored: {filed} stored/second-order finding(s)")
    return filed
