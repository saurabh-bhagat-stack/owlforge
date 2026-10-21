"""GraphQL introspection + field-suggestion checks."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    def __init__(self, introspection=True, suggestion=False):
        self.introspection = introspection
        self.suggestion = suggestion

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        b = body or ""
        if "__schema" in b:
            if self.introspection:
                return {"status": 200, "body": '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'}
            return {"status": 200, "body": '{"errors":[{"message":"introspection disabled"}]}'}
        if "__typ3name" in b:
            if self.suggestion:
                msg = 'Cannot query __typ3name. Did you mean \\"__typename\\"?'
                return {"status": 400, "body": '{"errors":[{"message":"' + msg + '"}]}'}
            return {"status": 400, "body": '{"errors":[{"message":"Cannot query field"}]}'}
        return {"status": 200, "body": '{"data":{"__typename":"Query"}}'}


INV = [{"url": "https://t/graphql", "method": "POST", "params": ["query"], "source": "graphql"}]


def test_introspection_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.graphqlscan import graphql_scan
    from owlforge.store.models import Finding
    assert graphql_scan("a1", INV, _SB(introspection=True), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "introspection" in f.title.lower() and f.status == "validated"


def test_suggestion_flagged_when_introspection_off(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.graphqlscan import graphql_scan
    from owlforge.store.models import Finding
    assert graphql_scan("a2", INV, _SB(introspection=False, suggestion=True), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a2")).one()
    assert "suggestion" in f.title.lower()


def test_locked_down_no_finding(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.graphqlscan import graphql_scan
    from owlforge.store.models import Finding
    assert graphql_scan("a3", INV, _SB(introspection=False, suggestion=False), {}) == 0
    with db.session() as s:
        assert s.exec(select(Finding).where(Finding.assessment_id == "a3")).all() == []
