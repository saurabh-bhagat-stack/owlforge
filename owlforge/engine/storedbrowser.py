"""Browser-driven stored/second-order XSS for formless + SPA UIs.

The static stored pass only submits to real <form> elements. Modern apps post via
JS/XHR with no <form>. This pass drives a real browser (agentd /interact): fill the
page's inputs with a payload, click submit, then re-check the page for execution —
catching stored XSS on formless/SPA inputs.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from urllib.parse import urlsplit


def browser_stored_scan(assessment_id: str, inventory: list[dict], sandbox,
                        session_headers: dict | None = None, cap: int = 6,
                        log: Callable[[str], None] = lambda m: None) -> int:
    """Drive the browser to submit a payload into each candidate page's inputs and check
    for execution on re-render. Files browser-confirmed VALIDATED findings. Bounded by
    `cap` (each interaction is a real browser session)."""
    if sandbox is None or not hasattr(sandbox, "interact"):
        return 0
    from owlforge.store.db import session
    from owlforge.store.models import Finding

    # candidate pages: real forms first, then content-ish pages (likely to hold inputs)
    cands: list[str] = []
    for it in inventory:
        if it.get("source") == "form":
            cands.append(it["url"])
    for it in inventory:
        u = it.get("url", "")
        if u and u not in cands and (it.get("params") or it.get("method", "GET").upper() == "GET"):
            cands.append(u)
    seen_paths: set[str] = set()
    uniq: list[str] = []
    for u in cands:
        key = urlsplit(u).path
        if key not in seen_paths:
            seen_paths.add(key)
            uniq.append(u)

    filed = 0
    done = 0
    for url in uniq:
        if done >= cap:
            break
        done += 1
        token = "owlsb" + secrets.token_hex(4)
        try:
            res = sandbox.interact(url, token, headers=session_headers or None, check_url=url) or {}
        except Exception:
            continue
        if not res.get("executed"):
            continue
        with session() as s:
            s.add(Finding(
                id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
                title=f"Stored/submitted XSS (fires on {url})", severity="high",
                endpoint=url, method="POST",
                technical_analysis=f"A payload submitted via the page's inputs at {url} EXECUTED on "
                                   f"re-render ({res.get('via')}). Browser-driven — covers formless/SPA "
                                   "inputs and stored sinks.",
                proof_of_concept=f"filled {res.get('filled')} field(s) with an XSS payload -> executed",
                evidence=f"window.__owl_xss == {token} on {url}",
                impact="Stored XSS runs in every browser that views the page.",
                remediation="Context-encode on output and sanitize stored input.",
                status="validated", confidence="high",
                validation_note=f"browser-driven submit executed — {res.get('via')}"))
            s.commit()
        filed += 1
        log(f"browser-stored: executed at {url}")
    return filed
