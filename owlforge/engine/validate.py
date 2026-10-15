"""Evidence-gated validation.

A candidate finding is only promoted to `validated` if its own proof reproduces:
we re-run the agent-supplied `repro_command` in the sandbox and require the
`success_signal` to appear in the output (or, if no signal was given, a zero exit).
This is the core owlforge principle — a finding is confirmed by re-test, not by the
model's assertion. Findings with no repro stay `candidate` (manual validation needed).
"""

from __future__ import annotations

import asyncio
import html
from datetime import UTC

from sqlmodel import select

from owlforge.engine.events import Emitter
from owlforge.sandbox.client import SandboxClient
from owlforge.store.db import session
from owlforge.store.models import Finding

_ACCESS_KEYWORDS = ("idor", "access control", "access-control", "authorization",
                    "broken access", "bola", "privilege escalation", "unauthor")


def _needs_differential(title: str) -> bool:
    """Access-control/IDOR can't be confirmed by a single successful request — a 200 with
    content is not proof of a boundary violation. These need differential testing
    (authorized vs unauthorized, or two accounts), which the signal gate cannot do."""
    t = (title or "").lower()
    return any(k in t for k in _ACCESS_KEYWORDS)


async def validate_findings(
    *, assessment_id: str, sandbox: SandboxClient | None, emit: Emitter
) -> dict[str, int]:
    with session() as s:
        rows = s.exec(
            select(Finding).where(
                Finding.assessment_id == assessment_id, Finding.status == "candidate"
            )
        ).all()
        items = [(f.id, f.repro_command, f.success_signal, f.title,
                  f.repro_method, f.repro_url, dict(f.repro_params or {}), f.repro_body) for f in rows]

    counts = {"validated": 0, "rejected": 0, "manual": 0}
    for fid, repro, signal, title, rmethod, rurl, rparams, rbody in items:
        if _needs_differential(title):
            _set(fid, "candidate", note=("access-control/IDOR needs differential testing "
                 "(authorized vs unauthorized / two accounts) — not auto-validated on a single request"))
            counts["manual"] += 1
            emit("log", f"access-control finding kept as candidate (needs differential): {title}")
            continue
        if not (rurl.strip() or repro.strip()):
            _set(fid, "candidate", note="no repro supplied — manual validation required")
            counts["manual"] += 1
            emit("log", f"manual-review (no repro): {title}")
            continue
        if sandbox is None:
            _set(fid, "candidate", note="no sandbox available to validate")
            counts["manual"] += 1
            continue
        try:
            if rurl.strip():
                from owlforge.tools.builtin import _normalize_params
                params = _normalize_params(rparams) if rparams else None
                d = await asyncio.to_thread(
                    sandbox.http_request, rmethod or "GET", rurl, params=params, body=(rbody or None)
                )
                out = f"{d.get('status', '')}\n{d.get('headers', '')}\n{d.get('body', '') or ''}".lower()
            else:
                r = await asyncio.to_thread(sandbox.exec, repro, timeout_ms=60_000)
                out = f"{r.stdout}\n{r.stderr}".lower()
            sig = signal.strip()
            if not sig:
                reproduced, reason = (r.exit_code == 0), "exit 0 (no signal supplied)"
            else:
                enc = html.escape(sig)
                if sig.lower() in out:
                    reproduced, reason = True, "signal reflected raw"
                elif enc.lower() != sig.lower() and enc.lower() in out:
                    # The marker is present ONLY in HTML-encoded form -> the input was
                    # escaped on output -> a reflection, not an executable injection.
                    reproduced, reason = False, "signal only present HTML-encoded (escaped) — not exploitable"
                else:
                    reproduced, reason = False, "signal not found in output"
        except Exception as e:
            _set(fid, "candidate", note=f"validation error: {type(e).__name__}: {e}")
            counts["manual"] += 1
            continue
        if reproduced:
            _set(fid, "validated", confidence="high", note=f"reproduced: {reason}")
            counts["validated"] += 1
            emit("finding_validated", f"VALIDATED: {title}")
        else:
            _set(fid, "false_positive", note=f"not reproduced: {reason}")
            counts["rejected"] += 1
            emit("finding_rejected", f"rejected ({reason}): {title}")
    return counts


def _set(finding_id: str, status: str, *, confidence: str | None = None, note: str = "") -> None:
    from datetime import datetime

    with session() as s:
        f = s.get(Finding, finding_id)
        if not f:
            return
        f.status = status
        if confidence:
            f.confidence = confidence
        if note:
            f.validation_note = note
        f.updated_at = datetime.now(UTC)
        s.add(f)
        s.commit()
