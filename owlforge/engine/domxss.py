"""Browser-driven XSS — catches DOM-based and JS-executing XSS that static/HTTP testing
cannot see. Injects a sentinel into the query param AND the URL fragment, renders in
real Chromium (agentd /xss_check), and files a browser-CONFIRMED finding when it
executes. No server reflection required — this is the DOM-sink path.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def browser_xss_scan(assessment_id: str, targets: list[dict], sandbox,
                     session_headers: dict | None = None, cap: int = 8,
                     log: Callable[[str], None] = lambda m: None) -> int:
    """Bounded browser-exec XSS sweep over `targets`. Files VALIDATED findings for any
    payload that executes (query-param reflected OR fragment/DOM sink). cap limits the
    number of renders (each is a real browser load)."""
    if sandbox is None or not hasattr(sandbox, "xss_check"):
        return 0
    from owlforge.store.db import session
    from owlforge.store.models import Finding

    renders = 0
    filed = 0
    seen: set[str] = set()
    for t in targets:
        if renders >= cap:
            break
        url = t["url"]
        p = t.get("param")
        token = "owldom" + secrets.token_hex(4)
        payloads = [
            f'"><img src=x onerror="window.__owl_xss=\'{token}\'">',
            f"<svg onload=window.__owl_xss='{token}'>",
            f"<img src=x onerror=window.__owl_xss='{token}'>",
        ]
        hit = None
        for pl in payloads:
            if renders >= cap:
                break
            sp = urlsplit(url)
            # (a) query param injection
            if p:
                q = dict(parse_qsl(sp.query))
                q[p] = pl
                u = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), ""))
                try:
                    renders += 1
                    if (sandbox.xss_check(u, token, headers=session_headers or None) or {}).get("executed"):
                        hit = (u, "query param -> executed in browser")
                        break
                except Exception:
                    pass
            # (b) URL fragment (DOM-based: server never sees it, JS sink does)
            uf = urlunsplit((sp.scheme, sp.netloc, sp.path, sp.query, pl))
            try:
                renders += 1
                if (sandbox.xss_check(uf, token, headers=session_headers or None) or {}).get("executed"):
                    hit = (uf, "URL fragment -> DOM sink executed in browser")
                    break
            except Exception:
                pass
        if not hit:
            continue
        key = f"{url}|{p}"
        if key in seen:
            continue
        seen.add(key)
        with session() as s:
            s.add(Finding(
                id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
                title=f"XSS (browser-confirmed{' DOM-based' if 'fragment' in hit[1] else ''})",
                severity="high", endpoint=url, method="GET",
                technical_analysis=f"A payload injected at {url} (param {p}) EXECUTED in a real "
                                   f"browser ({hit[1]}). This covers DOM/JS sinks invisible to HTTP tests.",
                proof_of_concept=f"{hit[0]}  -> window.__owl_xss == {token}",
                evidence=f"executed: {hit[0]}", impact="Script executes in the victim's browser.",
                remediation="Encode on output for the sink context; avoid unsafe DOM sinks "
                            "(innerHTML, document.write, eval) with untrusted input.",
                status="validated", confidence="high",
                validation_note=f"XSS executed in browser — {hit[1]}"))
            s.commit()
        filed += 1
        log(f"browser-XSS: executed at {hit[0]}")
    return filed
