"""Client-side prototype pollution (browser-verified).

Loads each candidate page with a query payload that pollutes Object.prototype via a common
sink shape, then confirms in real Chromium whether Object.prototype actually got the
sentinel property. Only a genuine pollution sink sets it -> deterministic, no false
positives. Bounded to a handful of pages.
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

_PROBE = "owlpp"
_SENTINEL = "owlPOLLUTED"
# common query-based pollution payload shapes
_PAYLOADS = (f"__proto__[{_PROBE}]={_SENTINEL}",
             f"constructor[prototype][{_PROBE}]={_SENTINEL}")


def _with_query(url: str, extra: str) -> str:
    p = urlsplit(url)
    q = (p.query + "&" if p.query else "") + extra
    return urlunsplit((p.scheme, p.netloc, p.path or "/", q, ""))


def _pages(inventory):
    seen, out = set(), []
    for it in inventory:
        u = it.get("url")
        if not u:
            continue
        key = urlsplit(u)._replace(query="").geturl()
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def _file(assessment_id, url, payload):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Client-side prototype pollution", severity="high",
            status="validated", confidence="high", endpoint=url, method="GET",
            technical_analysis=(f"Loading {url} with the query payload '{payload}' polluted "
                                "Object.prototype in the browser (confirmed: "
                                f"Object.prototype.{_PROBE} === '{_SENTINEL}'). The client "
                                "merges attacker-controlled keys into an object unsafely."),
            proof_of_concept=f"{url} ... ?{payload}  ->  Object.prototype.{_PROBE} set",
            impact="Prototype pollution can escalate to DOM XSS, logic bypass or RCE "
                   "depending on downstream gadget use.",
            remediation="Reject __proto__/constructor/prototype keys when merging untrusted "
                        "input; use Map or Object.create(null); freeze Object.prototype.",
            validation_note="confirmed by browser execution (Object.prototype polluted)"))
        s.commit()


def proto_pollution_scan(assessment_id, inventory, sandbox, session_headers,
                         log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None:
        return 0
    pages = _pages(inventory)[:8]
    if not pages:
        return 0
    filed = 0
    for url in pages:
        for payload in _PAYLOADS:
            try:
                r = sandbox.proto_check(_with_query(url, payload), _PROBE,
                                        headers=(session_headers or None))
            except Exception:
                continue
            if isinstance(r, dict) and r.get("polluted"):
                _file(assessment_id, url, payload)
                filed += 1
                break  # one confirmed payload per page is enough
    if filed:
        log(f"client-side: {filed} prototype-pollution sink(s) confirmed")
    return filed
