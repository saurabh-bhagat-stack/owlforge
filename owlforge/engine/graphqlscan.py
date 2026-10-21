"""GraphQL security checks — introspection + field suggestion.

For a discovered GraphQL endpoint: if introspection is enabled, the whole schema (types,
fields, mutations) is exposed to anyone; even with introspection off, "field suggestion"
("Did you mean …") leaks schema piecemeal. Both are deterministic, sound signals.
"""

from __future__ import annotations

import json
import secrets as _secrets
from collections.abc import Callable

_PATHS = ("/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/query", "/gql")


def _post(sandbox, url, query, headers):
    h = dict(headers or {})
    h["Content-Type"] = "application/json"
    try:
        return sandbox.http_request("POST", url, body=json.dumps({"query": query}),
                                    headers=h) or {}
    except Exception:
        return {}


def _endpoints(inventory, sandbox, headers, target):
    eps = [it["url"] for it in inventory if it.get("source") == "graphql" and it.get("url")]
    if eps:
        return list(dict.fromkeys(eps))
    # none in the surface -> probe common paths on the target origin
    from urllib.parse import urlsplit, urlunsplit
    if not target:
        return []
    b = urlsplit(target)
    found = []
    for p in _PATHS:
        u = urlunsplit((b.scheme, b.netloc, p, "", ""))
        r = _post(sandbox, u, "query{__typename}", headers)
        body = r.get("body", "") or ""
        if r.get("status") in (200, 400) and ("__typename" in body or '"data"' in body
                                              or '"errors"' in body):
            found.append(u)
    return found


def _file(assessment_id, url, title, severity, analysis, poc, note):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=title, severity=severity, status="validated", confidence="high",
            endpoint=url, method="POST", technical_analysis=analysis, proof_of_concept=poc,
            impact="Exposes the API's schema (types, fields, mutations), aiding targeted "
                   "attacks against the GraphQL API.",
            remediation="Disable introspection and field suggestions in production.",
            validation_note=note))
        s.commit()


def graphql_scan(assessment_id, inventory, sandbox, session_headers,
                 log: Callable[[str], None] = lambda m: None, target: str = "") -> int:
    if sandbox is None:
        return 0
    eps = _endpoints(inventory, sandbox, session_headers, target)
    if not eps:
        return 0
    filed = 0
    for url in eps[:5]:
        intro = _post(sandbox, url, "query{__schema{types{name}}}", session_headers)
        ibody = intro.get("body", "") or ""
        if "__schema" in ibody and '"types"' in ibody:
            _file(assessment_id, url, "GraphQL introspection enabled", "medium",
                  f"Introspection is enabled at {url}: a __schema query returns the full type "
                  "system, exposing every query, mutation and field to an attacker.",
                  "query{__schema{types{name}}} -> full schema returned",
                  "introspection query returned the schema (deterministic)")
            filed += 1
        else:
            sug = _post(sandbox, url, "query{__typ3name}", session_headers)
            sbody = (sug.get("body", "") or "").lower()
            if "did you mean" in sbody:
                _file(assessment_id, url, "GraphQL field suggestion enabled", "low",
                      f"Field suggestion is enabled at {url}: a mistyped field returns a "
                      "'Did you mean …' hint, leaking valid schema names even though "
                      "introspection is disabled.",
                      "query{__typ3name} -> 'Did you mean \"__typename\"?'",
                      "field-suggestion hint returned (deterministic)")
                filed += 1
    if filed:
        log(f"graphql: {filed} GraphQL schema-exposure finding(s)")
    return filed
