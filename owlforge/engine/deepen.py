"""Deepen — read-only proof escalation on validated findings.

After a finding is validated, a short focused agent escalates it to concrete,
non-destructive proof of impact (DBMS version for SQLi, id/hostname for RCE, one other
record for IDOR, internal reach for SSRF). The escalation is appended to the finding;
it never dumps bulk data, writes, or runs destructive payloads. Opt-in (costs a model).
"""

from __future__ import annotations

from owlforge.engine.agent import run_single_agent
from owlforge.engine.events import Emitter
from owlforge.tools.builtin import build_registry


def _deepen_instr(title: str, url: str, params: dict, signal: str) -> str:
    t = (title or "").lower()
    base = (f"A vulnerability is CONFIRMED: '{title}' at {url} (params {params}, signal '{signal}'). "
            "Escalate it to ONE concrete, READ-ONLY proof of impact, then call finish with that proof. "
            "Strict rules: read-only only — no writes, deletes, bulk dumps, or destructive payloads.")
    if "sql" in t:
        return base + (" For SQLi: identify the DBMS and extract a single low-sensitivity value "
                       "(version(), current_user, current_database()) via error/UNION. One value only.")
    if "command" in t or "rce" in t:
        return base + " For RCE: run only `id` and `hostname` (or equivalent) and report the output."
    if "idor" in t or "access" in t:
        return base + " For access control: show ONE other object/record you can reach that you should not."
    if "ssrf" in t:
        return base + " For SSRF: fetch a benign internal/metadata URL and show it resolved (no secrets dumped)."
    return base + " Obtain one piece of evidence that demonstrates impact, read-only."


async def deepen_findings(*, assessment_id: str, client, sandbox, emit: Emitter,
                          session_headers: dict | None = None, max_findings: int = 3,
                          max_turns: int = 6) -> int:
    from sqlmodel import select

    from owlforge.store.db import session
    from owlforge.store.models import Finding

    with session() as s:
        rows = s.exec(select(Finding).where(
            Finding.assessment_id == assessment_id, Finding.status == "validated")).all()
        # Skip findings the deterministic extractor already proved (e.g. SQLi whose
        # value was read out natively) — a model deepen pass adds nothing but a
        # contradictory "no value extracted" note next to the concrete value.
        items = [(f.id, f.title, f.repro_url, f.repro_method, dict(f.repro_params or {}),
                  f.success_signal or "") for f in rows
                 if "value-extracted" not in (f.validation_note or "")]

    registry = build_registry(with_sandbox=sandbox is not None)
    done = 0
    for fid, title, rurl, _rmethod, rparams, signal in items[:max_findings]:
        instr = _deepen_instr(title, rurl, rparams, signal)
        try:
            summary = await run_single_agent(
                client=client, registry=registry, emit=emit, assessment_id=assessment_id,
                target=rurl or "", instructions=instr, scan_mode="standard", max_turns=max_turns,
                sandbox=sandbox, session_headers=session_headers)
        except Exception as e:
            emit("log", f"deepen failed for {title}: {type(e).__name__}: {e}")
            continue
        if summary:
            with session() as s:
                f = s.get(Finding, fid)
                if f:
                    f.technical_analysis = (f.technical_analysis or "") + \
                        "\n\nEscalation (read-only proof): " + summary[:800]
                    s.add(f)
                    s.commit()
            emit("status", f"deepened: {title}")
            done += 1
    return done
