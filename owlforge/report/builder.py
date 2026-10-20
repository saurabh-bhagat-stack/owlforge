"""Assemble a markdown report from an assessment's findings and persist it."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import select

from owlforge.config import assessments_dir
from owlforge.store.db import session
from owlforge.store.models import Assessment, Finding, Report

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_and_save_report(assessment_id: str) -> tuple[str, str | None]:
    """Returns (markdown, file_path). Saves a Report row and writes report.md."""
    with session() as s:
        a = s.get(Assessment, assessment_id)
        findings = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
        findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
        validated = [f for f in findings if f.status in ("validated", "reported")]
        candidates = [f for f in findings if f.status == "candidate"]
        rejected = [f for f in findings if f.status == "false_positive"]

        sev = {k: sum(1 for f in validated if f.severity == k) for k in _SEV_ORDER}
        risk = next((k.capitalize() for k in _SEV_ORDER if sev[k] > 0), "Informational")
        target = a.target if a else assessment_id
        mode = a.scan_mode if a else ""

        md = _render(target, mode, risk, sev, validated, candidates, rejected)

        rep = s.get(Report, assessment_id) or Report(assessment_id=assessment_id)
        rep.status = "ready"
        rep.executive_summary = (
            f"{len(validated)} validated finding(s) "
            f"({sev['critical']}C/{sev['high']}H/{sev['medium']}M/{sev['low']}L), "
            f"{len(candidates)} unvalidated candidate(s). Overall risk: {risk}."
        )
        rep.risk_rating = risk
        rep.body_markdown = md
        rep.generated_at = datetime.now(UTC)
        s.add(rep)
        s.commit()

    path: str | None = None
    try:
        d = assessments_dir() / assessment_id
        d.mkdir(parents=True, exist_ok=True)
        fp = d / "report.md"
        fp.write_text(md, encoding="utf-8")
        path = str(fp)
    except Exception:
        pass
    # also emit HTML + SARIF (best-effort; never break the run)
    try:
        from owlforge.report.export import to_html, to_sarif
        to_html(assessment_id)
        to_sarif(assessment_id)
    except Exception:
        pass
    return md, path


def _render(target, mode, risk, sev, validated, candidates, rejected) -> str:
    lines = [
        f"# owlforge assessment report — {target}",
        "",
        f"- Scan mode: {mode}",
        f"- Overall risk: **{risk}**",
        f"- Validated: {len(validated)} | Candidates (unvalidated): {len(candidates)} "
        f"| Rejected: {len(rejected)}",
        f"- By severity (validated): {sev['critical']} critical, {sev['high']} high, "
        f"{sev['medium']} medium, {sev['low']} low, {sev['info']} info",
        "",
        "## Validated findings",
    ]
    if not validated:
        lines.append("\n_None validated with a reproducible proof-of-concept._")
    for f in validated:
        lines += _finding_block(f)

    if candidates:
        lines += ["", "## Candidates (need manual validation)"]
        for f in candidates:
            note = f" — _{f.validation_note}_" if f.validation_note else ""
            lines.append(f"- **[{f.severity}] {f.title}**{note}")

    return "\n".join(lines) + "\n"


def _finding_block(f: Finding) -> list[str]:
    out = [
        "",
        f"### [{f.severity.upper()}] {f.title}",
        f"- Status: {f.status} (confidence: {f.confidence})",
    ]
    if f.endpoint:
        out.append(f"- Endpoint: `{f.method or 'GET'} {f.endpoint}`")
    if f.validation_note:
        out.append(f"- Validation: {f.validation_note}")
    if f.technical_analysis:
        out += ["", "**Analysis**", "", f.technical_analysis]
    if f.proof_of_concept:
        out += ["", "**Proof of concept**", "", "```", f.proof_of_concept, "```"]
    if f.repro_command:
        out += ["", "**Reproduction**", "", "```", f.repro_command, "```"]
    if f.impact:
        out += ["", "**Impact**", "", f.impact]
    if f.remediation:
        out += ["", "**Remediation**", "", f.remediation]
    return out
