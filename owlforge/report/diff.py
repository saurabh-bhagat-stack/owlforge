"""Cross-run diff: compare an assessment's findings to a previous run of the same project.

Lets an operator (or CI) see what CHANGED between scans — new, fixed, and still-present
issues — instead of re-reading a full report each time.
"""

from __future__ import annotations

from urllib.parse import urlsplit

_LIVE = ("validated", "reported", "candidate")


def _norm_ep(ep: str | None) -> str:
    if not ep:
        return ""
    try:
        p = urlsplit(ep)
        return (p.path or ep).rstrip("/") or "/"
    except Exception:
        return ep


def _key(f) -> tuple[str, str]:
    return ((f.title or "").strip().lower(), _norm_ep(getattr(f, "endpoint", "")))


def diff_findings(current: list, previous: list) -> dict[str, list[tuple[str, str]]]:
    """Return {new, fixed, persisting} sets of (title, endpoint-path) keys."""
    cur = {_key(f) for f in current if getattr(f, "status", "") in _LIVE}
    prev = {_key(f) for f in previous if getattr(f, "status", "") in _LIVE}
    return {
        "new": sorted(cur - prev),
        "fixed": sorted(prev - cur),
        "persisting": sorted(cur & prev),
    }


def previous_assessment_id(assessment) -> str | None:
    """The most recent earlier assessment of the same project (else same target)."""
    from sqlmodel import select

    from owlforge.store.db import session
    from owlforge.store.models import Assessment
    with session() as s:
        rows = s.exec(select(Assessment)).all()
    cands = [a for a in rows if a.id != assessment.id
             and (a.created_at or 0) < (assessment.created_at or 0)
             and (a.project_name == assessment.project_name or a.target == assessment.target)]
    if not cands:
        return None
    cands.sort(key=lambda a: a.created_at or 0, reverse=True)
    return cands[0].id
