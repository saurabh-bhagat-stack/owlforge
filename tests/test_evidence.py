"""Evidence capture: validator stores request/response; reports render it."""
from __future__ import annotations

import asyncio


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        return {"status": 500, "headers": {"Server": "nginx"}, "body": "SQL error near ''"}


def test_validated_finding_gets_evidence(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Assessment, Finding
    with db.session() as s:
        s.add(Assessment(id="a", project_name="p", target="https://t", instructions="x", scan_mode="deep"))
        s.add(Finding(id="f1", assessment_id="a", title="SQL injection", severity="high",
                      status="candidate", endpoint="https://t/x", method="GET",
                      repro_url="https://t/x", repro_method="GET", repro_params={"id": "1'"},
                      success_signal="500"))
        s.commit()
    asyncio.run(validate_findings(assessment_id="a", sandbox=_SB(), emit=lambda *a, **k: None))
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.id == "f1")).one()
    assert f.status == "validated"
    assert f.evidence and "--- request ---" in f.evidence and "--- response ---" in f.evidence
    assert "HTTP 500" in f.evidence


def test_report_renders_evidence(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.report.builder import build_and_save_report
    from owlforge.report.export import to_html
    from owlforge.store.models import Assessment, Finding
    with db.session() as s:
        s.add(Assessment(id="a", project_name="p", target="https://t", instructions="x", scan_mode="deep"))
        s.add(Finding(id="f1", assessment_id="a", title="SQL injection", severity="high",
                      status="validated", endpoint="https://t/x", method="GET",
                      evidence="--- request ---\nGET https://t/x\n--- response ---\nHTTP 500"))
        s.commit()
    md, _ = build_and_save_report("a")
    assert "Evidence (request / response)" in md and "HTTP 500" in md
    html, _ = to_html("a")
    assert "Evidence (request / response)" in html
