"""Deepen a detected SQL injection with sqlmap (read-only).

owlforge's own differential/time-based checks detect SQLi; sqlmap then independently confirms
it and fingerprints the DBMS + current user/database for stronger, richer proof. Read-only
only — banner/current-user/current-db, never --dump of sensitive tables. Bounded to a couple
of findings (sqlmap is slow) and silent if sqlmap isn't in the image.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from urllib.parse import parse_qs, urlencode, urlsplit

_DBMS = re.compile(r"back-end DBMS: *([^\n]+)", re.I)
_DBMS2 = re.compile(r"the back-end DBMS is ([^\n.]+)", re.I)
_USER = re.compile(r"current user: *'?([^\n']+)", re.I)
_DB = re.compile(r"current database: *'?([^\n']+)", re.I)


def _target_url(url: str, params: dict) -> str:
    sp = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(sp.query).items()}
    for k in (params or {}):
        q.setdefault(k, "1")
    if not q:
        return url
    return sp._replace(query=urlencode(q)).geturl()


def sqlmap_confirm(assessment_id, sandbox, session_headers=None,
                   log: Callable[[str], None] = lambda m: None, cap: int = 2) -> int:
    """Run sqlmap (read-only) against already-detected SQLi findings; enrich them with the
    DBMS / current user / current database on confirmation. Returns the count confirmed."""
    if sandbox is None:
        return 0
    from sqlmodel import select

    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
        sqli = [f for f in rows
                if "sql injection" in (f.title or "").lower()
                and f.status in ("validated", "candidate")
                and (f.repro_url or f.endpoint)]
        items = [(f.id, f.repro_url or f.endpoint, dict(f.repro_params or {})) for f in sqli]

    if not items:
        return 0
    hdr = "".join(f" -H {shlex.quote(f'{k}: {v}')}" for k, v in (session_headers or {}).items())
    confirmed = 0
    for fid, url, params in items[:cap]:
        target = _target_url(url, params)
        cmd = (f"sqlmap -u {shlex.quote(target)} --batch --smart --level=2 --risk=2 "
               f"--technique=BEUST --banner --current-user --current-db --flush-session "
               f"--disable-coloring{hdr} 2>&1 | tail -80")
        try:
            r = sandbox.exec(cmd, timeout_ms=300_000)
        except Exception as e:
            log(f"sqlmap error: {e}")
            break
        out = (getattr(r, "stdout", "") or "")
        if getattr(r, "exit_code", 0) == 127 or "command not found" in (getattr(r, "stderr", "") or "").lower():
            log("sqlmap not available in the sandbox image (skip)")
            return 0
        low = out.lower()
        if "is vulnerable" not in low and "back-end dbms" not in low:
            continue
        dbms = (_DBMS.search(out) or _DBMS2.search(out))
        user = _USER.search(out)
        db = _DB.search(out)
        detail = "; ".join(x for x in [
            f"DBMS={dbms.group(1).strip()}" if dbms else "",
            f"current_user={user.group(1).strip()}" if user else "",
            f"current_db={db.group(1).strip()}" if db else "",
        ] if x) or "injection confirmed"
        with session() as s:
            f = s.get(Finding, fid)
            if f:
                f.status = "validated"
                f.confidence = "high"
                f.technical_analysis = ((f.technical_analysis or "").rstrip()
                                        + f"\n\nsqlmap confirmation (read-only): {detail}.")
                f.validation_note = ((f.validation_note or "") + " | sqlmap-confirmed").strip(" |")
                s.add(f)
                s.commit()
        confirmed += 1
    if confirmed:
        log(f"sqlmap: confirmed + enriched {confirmed} SQLi finding(s)")
    return confirmed
