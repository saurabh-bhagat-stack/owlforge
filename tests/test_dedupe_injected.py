"""Dedup keys on the INJECTED param, so same-param findings merge despite context params."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _statuses(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return {f.id: f.status for f in s.exec(select(Finding).where(Finding.assessment_id == "a")).all()}


def test_dedup_merges_same_injected_param(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.validate import dedupe_findings
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="f1", assessment_id="a", title="SQL injection (error-based)",
                      status="validated", severity="high", endpoint="https://t/catalog",
                      method="GET", repro_params={"category": "Gifts'"}))
        s.add(Finding(id="f2", assessment_id="a",
                      title="SQL Injection in `category` parameter (error-based)",
                      status="candidate", severity="high", endpoint="https://t/catalog",
                      method="GET", repro_params={"category": "Gifts'", "searchTerm": "test"}))
        s.commit()
    assert dedupe_findings("a") == 1
    st = _statuses(db)
    assert st["f1"] == "validated" and st["f2"] == "duplicate"


def test_dedup_keeps_distinct_injected_params(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.validate import dedupe_findings
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="f1", assessment_id="a", title="SQL injection in 'category'",
                      status="validated", severity="high", endpoint="https://t/catalog",
                      method="GET", repro_params={"category": "x'"}))
        s.add(Finding(id="f2", assessment_id="a", title="SQL injection in 'searchTerm'",
                      status="validated", severity="high", endpoint="https://t/catalog",
                      method="GET", repro_params={"searchTerm": "y'"}))
        s.commit()
    assert dedupe_findings("a") == 0           # different injected params -> both kept
    st = _statuses(db)
    assert st["f1"] == "validated" and st["f2"] == "validated"
