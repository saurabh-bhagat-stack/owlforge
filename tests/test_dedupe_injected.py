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


def test_dedup_merges_introspection_across_methods(tmp_path, monkeypatch):
    # an endpoint/config-level issue (GraphQL introspection) filed as both GET and POST is one
    # issue — method must not keep them apart.
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.validate import dedupe_findings
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="g1", assessment_id="a", title="GraphQL introspection enabled",
                      status="validated", severity="medium", endpoint="https://t/graphql",
                      method="POST"))
        s.add(Finding(id="g2", assessment_id="a", title="GraphQL introspection enabled",
                      status="candidate", severity="medium", endpoint="https://t/graphql",
                      method="GET"))
        s.commit()
    assert dedupe_findings("a") == 1
    st = _statuses(db)
    assert st["g1"] == "validated" and st["g2"] == "duplicate"


def test_dedup_keeps_distinct_injection_methods(tmp_path, monkeypatch):
    # a real injection finding is method-specific — GET vs POST must NOT be merged.
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.validate import dedupe_findings
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="h1", assessment_id="a", title="SQL injection in 'q'",
                      status="validated", severity="high", endpoint="https://t/x",
                      method="GET", repro_params={"q": "1'"}))
        s.add(Finding(id="h2", assessment_id="a", title="SQL injection in 'q'",
                      status="validated", severity="high", endpoint="https://t/x",
                      method="POST", repro_params={"q": "1'"}))
        s.commit()
    assert dedupe_findings("a") == 0           # different methods -> distinct sinks
