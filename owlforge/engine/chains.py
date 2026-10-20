"""M9 — exploit-chain correlation.

A deterministic post-validation pass that connects ALREADY-VALIDATED findings into
higher-impact attack narratives (e.g. harvested credentials -> authenticated access ->
IDOR/privilege escalation; SSRF -> cloud instance metadata). It is NON-DESTRUCTIVE: it
only describes a reachable escalation path built from steps owlforge already proved, and
records it as a clearly-labelled "Exploit chain:" finding referencing its components. It
never performs the next exploitation step itself.
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable

from sqlmodel import select

from owlforge.report.export import classify_finding
from owlforge.store.db import session
from owlforge.store.models import Assessment, Finding

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_sev(*sevs: str) -> str:
    best = max(sevs, key=lambda x: _SEV_RANK.get(x, 0))
    return best


def _metadata_reachable(f: Finding) -> bool:
    blob = " ".join([f.endpoint or "", f.proof_of_concept or "", f.repro_url or "",
                     f.validation_note or "", f.technical_analysis or ""]).lower()
    return any(m in blob for m in ("169.254.169.254", "metadata.google", "metadata.",
                                   "100.100.100.200", "/latest/meta-data"))


def correlate_chains(
    assessment_id: str,
    auth_summary: str = "",
    emit: Callable[..., None] = lambda *a, **k: None,
) -> int:
    """Create exploit-chain findings from validated components. Returns the count created."""
    authed = bool(auth_summary) and "unauth" not in (auth_summary or "").lower()

    with session() as s:
        a = s.get(Assessment, assessment_id)
        target = a.target if a else assessment_id
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
        validated = [f for f in rows if f.status in ("validated", "reported")]
        existing_titles = {f.title for f in rows}

        by_class: dict[str, list[Finding]] = {}
        for f in validated:
            cid, _cwe, _owasp = classify_finding(f)
            by_class.setdefault(cid, []).append(f)

        chains: list[dict] = []

        # 1) credentials -> authenticated access -> IDOR / privilege escalation
        ac = by_class.get("broken-access-control", [])
        if authed and ac:
            comp = ac[0]
            chains.append({
                "title": f"Exploit chain: credentialed access → {comp.title}",
                "severity": _max_sev("high", comp.severity),
                "endpoint": comp.endpoint,
                "analysis": (
                    "owlforge established an authenticated session "
                    f"({auth_summary.strip() or 'operator/discovered credentials'}) and then "
                    f"validated a broken-access-control issue ({comp.title}"
                    + (f" at {comp.method or 'GET'} {comp.endpoint}" if comp.endpoint else "")
                    + "). Chained, an attacker who obtains or is granted a low-privilege "
                    "account can reach data or actions outside their authorization — "
                    "horizontal/vertical privilege escalation. Steps are individually "
                    "validated; this entry correlates them (no further exploitation performed)."
                ),
                "impact": "Account/tenant isolation break: access to other users' data or "
                          "admin functionality from a low-privilege foothold.",
                "remediation": "Enforce server-side authorization on every object/route by the "
                               "caller's identity and role; deny by default.",
            })

        # 2) SSRF -> cloud instance metadata (credential exposure / pivot)
        for f in by_class.get("ssrf", []):
            if _metadata_reachable(f):
                chains.append({
                    "title": "Exploit chain: SSRF → cloud instance metadata",
                    "severity": "critical",
                    "endpoint": f.endpoint,
                    "analysis": (
                        f"The validated SSRF ({f.title}"
                        + (f" at {f.endpoint}" if f.endpoint else "")
                        + ") can reach the cloud instance metadata endpoint. In many "
                        "deployments this exposes temporary IAM/role credentials, enabling "
                        "a pivot into the cloud account. owlforge confirmed reachability "
                        "read-only and did NOT retrieve or use any credentials."
                    ),
                    "impact": "Potential theft of instance credentials and lateral movement "
                              "into internal/cloud infrastructure.",
                    "remediation": "Block egress to link-local metadata IPs, require IMDSv2/"
                                   "hop-limit, and allowlist outbound hosts.",
                })
                break

        created = 0
        for c in chains:
            if c["title"] in existing_titles:
                continue
            s.add(Finding(
                id=f"chain_{_secrets.token_hex(5)}",
                assessment_id=assessment_id,
                title=c["title"],
                severity=c["severity"],
                status="validated",
                confidence="medium",
                target=target,
                endpoint=c.get("endpoint"),
                technical_analysis=c["analysis"],
                impact=c["impact"],
                remediation=c["remediation"],
                validation_note="correlation of validated findings (non-destructive)",
            ))
            existing_titles.add(c["title"])
            created += 1
        if created:
            s.commit()

    if created:
        emit("status", f"chains — correlated {created} exploit chain(s)")
    return created
