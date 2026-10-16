"""Attempt ledger — what has been tried against each target.

Every http_request the agents make is recorded; specialists and the bypass loop read
a compact summary so they don't repeat payloads and know which vectors already failed
(so the next try is a DIFFERENT encoding/context, not the same thing again).
"""

from __future__ import annotations

import json
import secrets


def record_attempt(assessment_id: str, url: str, method: str, params: dict | None,
                   status: int, note: str = "") -> None:
    from owlforge.store.db import session
    from owlforge.store.models import Attempt

    try:
        with session() as s:
            s.add(Attempt(
                id=f"att_{secrets.token_hex(5)}", assessment_id=assessment_id,
                url=url, method=(method or "GET").upper(),
                param=",".join((params or {}).keys())[:120],
                payload=json.dumps(params or {}, default=str)[:400],
                status=int(status or 0), note=note[:200]))
            s.commit()
    except Exception:
        pass  # the ledger is best-effort; never break a request over it


def attempts_summary(assessment_id: str, url: str | None = None, limit: int = 25) -> str:
    """Compact text of prior attempts (optionally for one URL) for an agent's context."""
    from sqlmodel import select

    from owlforge.store.db import session
    from owlforge.store.models import Attempt

    try:
        with session() as s:
            q = select(Attempt).where(Attempt.assessment_id == assessment_id)
            if url:
                q = q.where(Attempt.url == url)
            rows = s.exec(q).all()
    except Exception:
        return ""
    rows = rows[-limit:]
    lines = [f"- {r.method} {r.url} {r.payload} -> {r.status}" + (f" ({r.note})" if r.note else "")
             for r in rows]
    return "\n".join(lines)
