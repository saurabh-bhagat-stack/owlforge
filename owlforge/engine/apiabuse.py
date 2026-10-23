"""API body/variable fuzzing — injection probes aimed at JSON request BODIES.

The orchestrator's specialists and pre-probe put payloads in query/form parameters. Strict
JSON APIs take their inputs in the request body, so those fields can go untested. This pass
fuzzes each JSON body field (derived from the spec params owlforge ingests) with the same
deterministic, evidence-gated signals the rest of the engine trusts:

  SSTI  {{1337*1337}} -> 1787569          (validated)
  path  ../../etc/passwd -> root:x:0:0     (validated)
  cmd   ; id -> uid=…(…)                    (validated)
  SQLi  ' -> a 5xx/error that a benign value did not cause   (candidate, error-based)

Each probe is a differential: a baseline request with benign values is sent first, and a
signal only counts when it appears for the mutated field and NOT for the baseline. Bounded
and best-effort; it only sends what the spec already describes.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable

# (id, payload, signal, is_regex, severity, status) — signal None means "use the status differential"
_PROBES = (
    ("ssti", "{{1337*1337}}", "1787569", False, "high", "validated"),
    ("ssti", "${1337*1337}", "1787569", False, "high", "validated"),
    ("path", "../../../../../../../../etc/passwd", "root:x:0:0", False, "high", "validated"),
    ("cmd", "; id", r"uid=\d+\([^)]*\)", True, "high", "validated"),
    ("cmd", "`id`", r"uid=\d+\([^)]*\)", True, "high", "validated"),
    ("sqli", "'", None, False, "medium", "candidate"),
)
_SQL_ERR = ("sql syntax", "sqlstate", "odbc", "psql", "pg::", "sqlite", "mysql", "ora-",
            "unclosed quotation", "syntax error at or near", "unterminated")
_TITLE = {
    "ssti": "Server-side template injection (SSTI) in API body field",
    "path": "Path traversal / local file read via API body field",
    "cmd": "OS command injection via API body field",
    "sqli": "Possible SQL injection in API body field (error-based)",
}
_REMED = {
    "ssti": "Never render user input as a template; use a sandboxed/logic-less engine and "
            "pass data as context, not source.",
    "path": "Resolve and canonicalise paths against an allow-listed base directory; reject "
            "traversal sequences; do not build file paths from user input.",
    "cmd": "Never pass user input to a shell; use parameterised APIs / exec with an argument "
           "vector and strict allow-lists.",
    "sqli": "Use parameterised queries / prepared statements; never concatenate input into SQL.",
}


def _is_api(it, url):
    low = (url or "").lower()
    return it.get("source") in ("api-spec", "graphql") or "/api/" in low or "/graphql" in low


def _targets(inventory):
    seen, out = set(), []
    for it in inventory or []:
        url = it.get("url") or ""
        method = (it.get("method") or "GET").upper()
        params = [p for p in (it.get("params") or []) if p]
        if method not in ("POST", "PUT", "PATCH") or not params or not _is_api(it, url):
            continue
        key = (method, url)
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": url, "method": method, "params": params})
    return out


def _send_json(sandbox, method, url, obj, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = "application/json"
        return sandbox.http_request(method, url, headers=h, body=json.dumps(obj),
                                    follow_redirects=False) or {}
    except Exception:
        return {}


def _hit(sig, is_regex, resp, base_body, base_status) -> bool:
    body = resp.get("body", "") or ""
    status = int(resp.get("status") or 0)
    if sig is None:                              # SQLi: error/5xx the benign value did not cause
        low = body.lower()
        base_ok = int(base_status or 0) < 500 and not any(k in base_body.lower() for k in _SQL_ERR)
        return base_ok and (status >= 500 or any(k in low for k in _SQL_ERR))
    if is_regex:
        return bool(re.search(sig, body)) and not re.search(sig, base_body)
    return sig in body and sig not in base_body


def _file(assessment_id, cls, url, method, field, payload, status):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"{_TITLE[cls]} '{field}'",
            severity=dict(ssti="high", path="high", cmd="critical", sqli="medium")[cls],
            status=status, confidence="high" if status == "validated" else "medium",
            endpoint=url, method=method,
            technical_analysis=(
                f"The JSON body field '{field}' at {method} {url} is injectable: sending "
                f"{payload!r} produced the expected proof while a benign value did not."),
            proof_of_concept=f'{method} {url} with JSON body {{"{field}": {payload!r}}}',
            impact="See the vulnerability class — ranges from data/file disclosure to remote "
                   "code execution depending on the sink.",
            remediation=_REMED[cls],
            repro_url=url, repro_method=method,
            repro_body=json.dumps({field: payload}), repro_content_type="application/json",
            validation_note="API JSON-body injection confirmed by a baseline-vs-payload differential"))
        s.commit()


def api_fuzz_scan(assessment_id, inventory, sandbox, session_headers,
                  log: Callable[[str], None] = lambda m: None, cap: int = 8,
                  field_cap: int = 6) -> int:
    """Fuzz JSON body fields of API endpoints with sound injection probes. Returns count filed."""
    if sandbox is None:
        return 0
    targets = _targets(inventory)
    if not targets:
        return 0
    filed = tested = 0
    for t in targets[:cap]:
        tested += 1
        benign = {p: f"owl{secrets.token_hex(3)}" for p in t["params"]}
        base = _send_json(sandbox, t["method"], t["url"], benign, session_headers)
        base_body, base_status = base.get("body", "") or "", int(base.get("status") or 0)
        for field in t["params"][:field_cap]:
            done = False
            for cls, payload, sig, is_regex, _sev, status_kind in _PROBES:
                body = dict(benign)
                body[field] = payload
                resp = _send_json(sandbox, t["method"], t["url"], body, session_headers)
                if _hit(sig, is_regex, resp, base_body, base_status):
                    _file(assessment_id, cls, t["url"], t["method"], field, payload, status_kind)
                    log(f"api-fuzz: {cls} in body field '{field}' at {t['method']} {t['url']}")
                    filed += 1
                    done = True
                    break
            if done:
                continue
    if filed:
        log(f"api-fuzz: {filed} API body-injection finding(s) across {tested} endpoint(s)")
    return filed
