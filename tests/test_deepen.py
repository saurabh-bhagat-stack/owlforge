"""Deepen — read-only proof escalation."""

from __future__ import annotations

import asyncio


def test_deepen_appends_escalation_to_validated_finding(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    from sqlmodel import select

    from owlforge.engine.deepen import deepen_findings
    from owlforge.engine.events import Emitter
    from owlforge.llm.base import AssistantTurn, ToolCall
    from owlforge.store.models import Finding

    with db.session() as s:
        s.add(Finding(id="v1", assessment_id="asmt_d", title="SQL Injection in category",
                      severity="high", status="validated", repro_url="https://t/catalog",
                      repro_method="GET", repro_params={"category": "'"}, success_signal="500"))
        s.commit()

    class _Client:
        def chat(self, messages, tools=None, *, temperature=None, max_tokens=None):
            return AssistantTurn(content=None, tool_calls=[ToolCall(
                id="f1", name="finish", arguments={"summary": "DBMS is PostgreSQL 14.2 (version() extracted)"})])

    n = asyncio.run(deepen_findings(assessment_id="asmt_d", client=_Client(), sandbox=None,
                                    emit=Emitter("asmt_d", persist=False)))
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.id == "v1")).one()
    assert "Escalation" in f.technical_analysis and "PostgreSQL" in f.technical_analysis


def test_deepen_skips_findings_already_value_extracted(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    from sqlmodel import select

    from owlforge.engine.deepen import deepen_findings
    from owlforge.engine.events import Emitter
    from owlforge.llm.base import AssistantTurn, ToolCall
    from owlforge.store.models import Finding

    with db.session() as s:
        # already proven by the deterministic extractor -> deepen must NOT touch it
        s.add(Finding(id="x1", assessment_id="asmt_x", title="SQL injection (error-based)",
                      severity="high", status="validated", repro_url="https://t/catalog",
                      repro_method="GET", repro_params={"category": "1'"}, success_signal="500",
                      validation_note="reproduced | value-extracted"))
        # not extracted -> deepen should still run on this one
        s.add(Finding(id="x2", assessment_id="asmt_x", title="OS command injection",
                      severity="high", status="validated", repro_url="https://t/ping",
                      repro_method="GET", repro_params={"host": "x"}, success_signal="uid="))
        s.commit()

    class _Client:
        def chat(self, messages, tools=None, *, temperature=None, max_tokens=None):
            return AssistantTurn(content=None, tool_calls=[ToolCall(
                id="f1", name="finish", arguments={"summary": "escalated: ran id -> uid=33"})])

    n = asyncio.run(deepen_findings(assessment_id="asmt_x", client=_Client(), sandbox=None,
                                    emit=Emitter("asmt_x", persist=False)))
    assert n == 1   # only the non-extracted finding was deepened
    with db.session() as s:
        extracted = s.exec(select(Finding).where(Finding.id == "x1")).one()
        other = s.exec(select(Finding).where(Finding.id == "x2")).one()
    assert "Escalation" not in (extracted.technical_analysis or "")   # left untouched
    assert "Escalation" in (other.technical_analysis or "")

