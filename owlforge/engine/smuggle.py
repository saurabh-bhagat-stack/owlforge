"""HTTP request-smuggling detection (best-effort, time-based CL.TE/TE.CL).

Detection only — a large read-timing anomaly on an ambiguous Content-Length+Transfer-
Encoding request suggests a front/back-end desync. Files a LOW-confidence candidate for
manual confirmation (full exploitation is deliberately not automated).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable


def smuggle_scan(assessment_id: str, target: str, sandbox,
                 log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None or not hasattr(sandbox, "smuggle_probe"):
        return 0
    try:
        res = sandbox.smuggle_probe(target)
    except Exception as e:
        log(f"smuggle probe error: {e}")
        return 0
    if res.get("error") or not res.get("potential"):
        log(f"smuggle: no desync (baseline={res.get('baseline_s')}s "
            f"clte={res.get('clte_s')}s tecl={res.get('tecl_s')}s)")
        return 0
    from owlforge.store.db import session
    from owlforge.store.models import Finding

    kind = res.get("kind") or "CL.TE/TE.CL"
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Potential HTTP request smuggling ({kind})", severity="high",
            endpoint=target, method="POST",
            technical_analysis=f"An ambiguous Content-Length + Transfer-Encoding request to {target} "
                               f"hung far longer than baseline ({kind} timing anomaly: "
                               f"baseline={res.get('baseline_s')}s vs probe={res.get('clte_s')}/"
                               f"{res.get('tecl_s')}s), suggesting a front/back-end desync.",
            proof_of_concept=f"{kind} time-based probe (see timings)",
            evidence=f"baseline={res.get('baseline_s')}s clte={res.get('clte_s')}s tecl={res.get('tecl_s')}s",
            impact="Request smuggling can poison other users' requests / bypass front-end controls.",
            remediation="Normalize/reject ambiguous CL+TE; use HTTP/2 end-to-end; align front/back-end parsing.",
            status="candidate", confidence="low",
            validation_note="time-based desync signal — confirm manually (detection only)"))
        s.commit()
    log(f"smuggle: POTENTIAL {kind} desync on {target}")
    return 1
