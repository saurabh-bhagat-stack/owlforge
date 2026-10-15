"""Phase 3: typed findings, evidence-gated validation, report assembly."""

from __future__ import annotations

import asyncio

import pytest

from owlforge.engine.events import Emitter
from owlforge.sandbox.client import ExecResult


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import owlforge.config as config
    import owlforge.store.db as db

    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _FakeSandbox:
    def __init__(self, out: str) -> None:
        self.out = out

    def exec(self, command: str, *, workdir=None, timeout_ms=60_000) -> ExecResult:
        return ExecResult(exit_code=0, stdout=self.out, stderr="", duration_ms=1)

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
        # emulate ginandjuice: a lone quote in category -> 500, else 200
        q = (params or {}).get("category", "")
        status = 500 if q == "'" else 200
        return {"status": status, "headers": {}, "body": self.out}


def _mk(db, **kw):
    from owlforge.store.models import Finding

    f = Finding(assessment_id="asmt_x", status="candidate", **kw)
    with db.session() as s:
        s.add(f)
        s.commit()
        return f.id


def test_validation_promotes_on_signal_rejects_without_and_manual_without_repro(isolated):
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    good = _mk(isolated, id="f_good", title="LFI /etc/passwd", severity="high",
               repro_command="curl .../?file=/etc/passwd", success_signal="root:x:0:0")
    bad = _mk(isolated, id="f_bad", title="maybe xss", severity="low",
              repro_command="curl ...", success_signal="UNIQUE_MARKER_123")
    manual = _mk(isolated, id="f_manual", title="suspected info disclosure", severity="medium")

    # sandbox output contains the good signal but not the bad one
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_FakeSandbox("root:x:0:0:root:/root:/bin/bash"),
        emit=Emitter("asmt_x", persist=False)))

    assert counts == {"validated": 1, "rejected": 1, "manual": 1}
    with isolated.session() as s:
        assert s.get(Finding, good).status == "validated"
        assert s.get(Finding, bad).status == "false_positive"
        assert s.get(Finding, manual).status == "candidate"
        assert "manual" in s.get(Finding, manual).validation_note.lower()


def test_report_build(isolated):
    from owlforge.report.builder import build_and_save_report
    from owlforge.store.models import Assessment, Finding

    with isolated.session() as s:
        s.add(Assessment(id="asmt_x", project_name="p", target="https://t.test",
                         instructions="i", scan_mode="standard", status="reporting"))
        s.add(Finding(id="f1", assessment_id="asmt_x", title="SQLi login", severity="critical",
                      status="validated", confidence="high", endpoint="/login",
                      proof_of_concept="' OR 1=1--", repro_command="sqlmap ...",
                      impact="auth bypass", remediation="use params"))
        s.commit()

    md, path = build_and_save_report("asmt_x")
    assert "SQLi login" in md and "Overall risk: **Critical**" in md
    assert path and path.endswith("report.md")


def test_create_finding_tool_persists_no_detached_error(isolated):
    from sqlmodel import select

    from owlforge.store.models import Finding
    from owlforge.tools.base import ToolContext
    from owlforge.tools.builtin import build_registry

    tool = build_registry(with_sandbox=False).get("create_finding")
    assert tool is not None
    ctx = ToolContext(assessment_id="asmt_x", target="https://t.test", emit=Emitter("asmt_x", persist=False))
    out = asyncio.run(tool.run(
        {"title": "Test XSS", "severity": "high", "repro_command": "curl x", "success_signal": "X"}, ctx))
    assert "filed as candidate" in out and "error" not in out.lower()
    with isolated.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "asmt_x")).all()
    assert len(rows) == 1 and rows[0].title == "Test XSS"


def test_validation_rejects_html_encoded_only_reflection(isolated):
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    fid = _mk(isolated, id="f_esc", title="reflected XSS?", severity="high",
              repro_command="curl ...", success_signal="<script>owl</script>")
    # Sandbox returns the payload ONLY in HTML-encoded form -> escaped -> not exploitable.
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x",
        sandbox=_FakeSandbox("var s = '&lt;script&gt;owl&lt;/script&gt;';"),
        emit=Emitter("asmt_x", persist=False)))
    assert counts["rejected"] == 1 and counts["validated"] == 0
    with isolated.session() as s:
        assert s.get(Finding, fid).status == "false_positive"


def test_normalize_params_prevents_double_encoding():
    from owlforge.tools.builtin import _normalize_params

    # pre-encoded payload gets decoded once (so httpx encodes exactly once on the wire)
    assert _normalize_params({"category": "Accessories%27"}) == {"category": "Accessories'"}
    # raw payload is left as-is
    assert _normalize_params({"category": "Accessories'"}) == {"category": "Accessories'"}
    # plain values untouched
    assert _normalize_params({"q": "plain"}) == {"q": "plain"}


def test_playbooks_teach_enumeration_and_confirmation():
    from owlforge.knowledge import load_playbooks, render_playbooks

    names = {p["name"] for p in load_playbooks()}
    assert {"methodology", "sql_injection", "xss", "path_traversal"} <= names
    text = render_playbooks()
    # the discovery-gap fix: enumerate ALL params, not just the obvious one
    assert "EVERY input point" in text
    assert "BREADTH BEFORE DEPTH" in text
    # the escaped-reflection lesson
    assert "HTML-ENCODED" in text and "NOT exploitable" in text


def test_system_prompt_includes_playbooks():
    from owlforge.engine.prompts import system_prompt

    sp = system_prompt("https://t.test", "assess it", "standard")
    assert "Methodology & playbooks" in sp and "SQL injection" in sp


def test_access_control_finding_not_auto_validated(isolated):
    import asyncio

    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    fid = _mk(isolated, id="f_idor", title="Broken Access Control / IDOR on products",
              severity="high", repro_command="curl .../product?productId=2", success_signal="Cocktail")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_FakeSandbox("... Create Your Own Cocktail ..."),
        emit=Emitter("asmt_x", persist=False)))
    # signal WOULD be present, but access-control must NOT auto-validate
    assert counts["validated"] == 0 and counts["manual"] == 1
    with isolated.session() as s:
        f = s.get(Finding, fid)
        assert f.status == "candidate" and "differential" in f.validation_note.lower()


def test_migration_adds_missing_column(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import importlib

    import owlforge.config as config
    importlib.reload(config)
    import owlforge.store.db as db
    importlib.reload(db)
    from sqlalchemy import text

    db._engine = None
    db.init_db()
    # simulate an OLD schema: drop a column by recreating a stripped finding table is hard;
    # instead, add then verify idempotency + that a known new column exists after migrate.
    with db.get_engine().begin() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info('finding')")).all()]
    assert "repro_command" in cols and "success_signal" in cols and "validation_note" in cols
    # simulate stale table missing 'validation_note'
    with db.get_engine().begin() as conn:
        conn.execute(text("ALTER TABLE finding DROP COLUMN validation_note"))
        cols2 = [r[1] for r in conn.execute(text("PRAGMA table_info('finding')")).all()]
    assert "validation_note" not in cols2
    db.init_db()  # migration should re-add it
    with db.get_engine().begin() as conn:
        cols3 = [r[1] for r in conn.execute(text("PRAGMA table_info('finding')")).all()]
    assert "validation_note" in cols3


def test_structured_repro_validates_via_http_request(isolated):
    import asyncio

    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    fid = _mk(isolated, id="f_sqli", title="SQL Injection in category parameter", severity="high",
              repro_url="https://t/catalog", repro_method="GET",
              repro_params={"category": "'"}, success_signal="500")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_FakeSandbox(""), emit=Emitter("asmt_x", persist=False)))
    assert counts["validated"] == 1
    with isolated.session() as s:
        assert s.get(Finding, fid).status == "validated"
