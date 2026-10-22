"""Cross-actor edit/delete matrix on seeded objects (broken function-level authz)."""
from __future__ import annotations

from urllib.parse import parse_qs


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _seed(db, url="https://t/posts/42"):
    from owlforge.store.models import SurfaceItem
    with db.session() as s:
        s.add(SurfaceItem(id="s1", assessment_id="a", url=url, method="GET",
                          params=[], source="seeded"))
        s.commit()


OWNER = {"Cookie": "owner=1"}
USERB = {"Cookie": "b=1"}


class _App:
    """A tiny object with an edit form + a delete endpoint, and a configurable authz policy."""

    def __init__(self, *, allow_nonowner_edit=False, allow_nonowner_delete=False):
        self.title = "owner post"
        self.exists = True
        self.ae = allow_nonowner_edit
        self.ad = allow_nonowner_delete

    def _is_owner(self, headers):
        return (headers or {}).get("Cookie") == "owner=1"

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/posts/42") and method == "GET":
            if not self.exists:
                return {"status": 404, "headers": {}, "body": "not found"}
            page = (f"<h1>{self.title}</h1>"
                    f'<form action="/posts/42" method="post">'
                    f'<input type="hidden" name="csrf" value="T">'
                    f'<input name="title" value="{self.title}"></form>'
                    f'<a href="/posts/42/delete">delete</a>')
            return {"status": 200, "headers": {}, "body": page}
        if url.endswith("/posts/42") and method == "POST":           # edit
            if self._is_owner(headers) or self.ae:
                q = parse_qs(body or "")
                self.title = q.get("title", [self.title])[0]
                return {"status": 302, "headers": {"location": "/posts/42"}, "body": ""}
            return {"status": 403, "headers": {}, "body": "forbidden"}
        if ("/posts/42/delete" in url) or (url.endswith("/posts/42") and method == "DELETE"):
            if self._is_owner(headers) or self.ad:
                self.exists = False
                return {"status": 302, "headers": {"location": "/posts"}, "body": ""}
            return {"status": 403, "headers": {}, "body": "forbidden"}
        return {"status": 404, "headers": {}, "body": ""}


_IDENT = [{"label": "session", "headers": OWNER}, {"label": "userB", "headers": USERB}]


def _titles(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a")).all()]


def test_nonowner_edit_is_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from owlforge.engine.authmatrix import access_matrix_scan
    n = access_matrix_scan("a", _App(allow_nonowner_edit=True), OWNER, _IDENT)
    assert n >= 1
    assert any("can edit" in t for t in _titles(db))


def test_nonowner_delete_is_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from owlforge.engine.authmatrix import access_matrix_scan
    n = access_matrix_scan("a", _App(allow_nonowner_delete=True), OWNER, _IDENT)
    assert n >= 1
    assert any("can delete" in t for t in _titles(db))


def test_secure_app_no_findings(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from owlforge.engine.authmatrix import access_matrix_scan
    assert access_matrix_scan("a", _App(), OWNER, _IDENT) == 0
    assert _titles(db) == []


def test_no_seeded_objects_noop(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.authmatrix import access_matrix_scan
    assert access_matrix_scan("a", _App(allow_nonowner_edit=True), OWNER, _IDENT) == 0
