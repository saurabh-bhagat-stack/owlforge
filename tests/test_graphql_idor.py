"""GraphQL cross-session IDOR/BOLA on owlforge-created objects."""
from __future__ import annotations

import json


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _findings(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return s.exec(select(Finding).where(Finding.assessment_id == "a")).all()


OWNER = {"Cookie": "owner=1"}
_SEEDED = [{"source": "seeded-graphql", "object_id": "5", "read_field": "post",
            "endpoint": "https://t/graphql"}]
_IDENTS = [{"label": "userB", "headers": {"Cookie": "b=1"}}]


class _GqlReadApp:
    """post(id:5) returns the node either for everyone (vulnerable) or only the owner."""

    def __init__(self, private):
        self.private = private

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        q = (json.loads(body or "{}").get("query", "") if body else "")
        if "post(id:5)" in q.replace(" ", ""):
            if self.private and (headers or {}).get("Cookie") != "owner=1":
                return {"status": 200, "headers": {}, "body": '{"data":{"post":null}}'}
            return {"status": 200, "headers": {}, "body": '{"data":{"post":{"id":"5"}}}'}
        return {"status": 200, "headers": {}, "body": '{"data":{}}'}


def test_graphql_bola_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.graphqlscan import graphql_idor_scan
    n = graphql_idor_scan("a", _SEEDED, _GqlReadApp(private=False), OWNER, _IDENTS)
    assert n >= 1
    assert any("object-level authorization" in x.title.lower() and x.status == "candidate"
               for x in _findings(db))


def test_graphql_private_object_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.graphqlscan import graphql_idor_scan
    n = graphql_idor_scan("a", _SEEDED, _GqlReadApp(private=True), OWNER, _IDENTS)
    assert n == 0
    assert _findings(db) == []
