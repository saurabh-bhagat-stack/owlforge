"""Deterministic CORS misconfiguration probe.

Sends a request with an attacker `Origin` and inspects the CORS response headers. A server
that **reflects an arbitrary Origin** into `Access-Control-Allow-Origin` is misconfigured;
if it also sets `Access-Control-Allow-Credentials: true`, any site can read this origin's
authenticated responses in a victim's browser (CWE-942). Reflection of our unique marker
origin is the proof — `*` alone is NOT flagged (public APIs use it and browsers block
`*`+credentials). Sound, generic, non-destructive (one extra GET per endpoint).
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable
from urllib.parse import urlsplit

_EVIL = "https://owlforge-cors-probe.example"


def _endpoints(inventory) -> list[tuple[str, str]]:
    seen, out = set(), []
    for it in inventory or []:
        url = it.get("url")
        method = (it.get("method") or "GET").upper()
        if not url or method not in ("GET", "POST"):
            continue
        key = urlsplit(url)._replace(query="").geturl()
        if key in seen:
            continue
        seen.add(key)
        out.append((url, method))
    return out


def _file(assessment_id, url, method, title, severity, note, acao, acac):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=title, severity=severity, status="validated", confidence="high",
            endpoint=url, method=method,
            technical_analysis=(
                f"The endpoint reflects an attacker-controlled Origin into its CORS response: "
                f"Access-Control-Allow-Origin: {acao}"
                + (f"; Access-Control-Allow-Credentials: {acac}" if acac else "") + ". " + note),
            proof_of_concept=(
                f"{method} {url} with `Origin: {_EVIL}` -> `Access-Control-Allow-Origin: {acao}`"
                + (f", `Access-Control-Allow-Credentials: {acac}`" if acac else "")),
            impact="A malicious web page can read this origin's cross-origin responses in a "
                   "victim's authenticated browser session.",
            remediation="Validate the Origin against a strict allowlist; never reflect it, and "
                        "do not combine credentialed responses with a permissive Origin.",
            validation_note="reproduced: attacker Origin reflected in Access-Control-Allow-Origin "
                            "(deterministic)"))
        s.commit()


def cors_scan(assessment_id, inventory, sandbox, session_headers,
              log: Callable[[str], None] = lambda m: None) -> int:
    """Probe CORS reflection on the discovered surface; auto-file confirmed
    misconfigurations. Returns the count filed."""
    if sandbox is None:
        return 0
    targets = _endpoints(inventory)
    if not targets:
        return 0
    filed = tested = 0
    for url, method in targets[:15]:
        try:
            r = sandbox.http_request(method, url,
                                     headers={**(session_headers or {}), "Origin": _EVIL},
                                     params=None, body=None) or {}
        except Exception:
            continue
        tested += 1
        hdrs = {str(k).lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        acao = hdrs.get("access-control-allow-origin", "").strip()
        acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
        if acao == _EVIL and acac == "true":
            _file(assessment_id, url, method,
                  "CORS misconfiguration: credentialed cross-origin read", "high",
                  "Credentials are allowed with a reflected origin — fully exploitable.", acao, acac)
            filed += 1
        elif acao == _EVIL:
            _file(assessment_id, url, method,
                  "CORS misconfiguration: arbitrary origin reflected", "medium",
                  "Any origin is allowed to read non-credentialed cross-origin responses.", acao, "")
            filed += 1
        elif acao == "null":
            _file(assessment_id, url, method,
                  "CORS misconfiguration: null origin allowed", "medium",
                  "The 'null' origin is allowed (reachable from sandboxed iframes/documents).",
                  acao, acac)
            filed += 1
    if filed:
        log(f"cors: {filed} CORS misconfiguration(s) confirmed")
    elif tested:
        log(f"cors: no origin reflection on {tested} endpoint(s)")
    return filed
