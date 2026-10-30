"""Authenticated API-surface discovery: recover prefixed object endpoints from the JS bundle."""
from __future__ import annotations

import urllib.parse as up


class _Exec:
    def __init__(self, out):
        self.stdout = out
        self.exit_code = 0
        self.stderr = ""


class _ApiApp:
    """A microservice SPA: /identity is the gateway; its authed API answers only with a bearer.
    sandbox.exec simulates curl|grep returning the API literals from the (untruncated) bundle."""

    def exec(self, command, **kw):
        return _Exec("api/v2/user/dashboard\napi/v2/user/videos\napi/auth/login")

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        path = up.urlsplit(url).path
        if path == "/":
            return {"status": 200, "body": '<script src="/static/js/main.abc.js"></script>'}
        if path == "/identity":
            return {"status": 301, "body": ""}                       # gateway prefix exists
        if path.startswith("/identity/api/v2/user/"):
            if headers and "Authorization" in headers:
                return {"status": 200, "body": '{"id":1,"email":"a@b.c"}'}   # authed object API
            return {"status": 401, "body": "no"}
        return {"status": 404, "body": "nf"}


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def test_recovers_prefixed_authed_endpoints(tmp_path, monkeypatch):
    from sqlmodel import select

    from owlforge.engine.apisurface import discover_api_endpoints
    from owlforge.store.models import SurfaceItem
    db = _db(tmp_path, monkeypatch)
    n = discover_api_endpoints("a", [], _ApiApp(), "https://t/",
                               {"Authorization": "Bearer x"}, log=lambda m: None)
    assert n >= 1
    with db.session() as s:
        urls = [it.url for it in s.exec(select(SurfaceItem).where(SurfaceItem.assessment_id == "a"))]
    assert any(u.endswith("/identity/api/v2/user/dashboard") for u in urls)   # right prefix applied
    with db.session() as s:
        srcs = {i.source for i in s.exec(select(SurfaceItem).where(SurfaceItem.assessment_id == "a"))}
    assert srcs == {"js-api"}


def test_no_literals_no_endpoints(tmp_path, monkeypatch):
    from owlforge.engine.apisurface import discover_api_endpoints

    class _Empty:
        def exec(self, command, **kw):
            return _Exec("")
        def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
            return {"status": 200, "body": "<html>no scripts</html>"} if up.urlsplit(url).path == "/" \
                else {"status": 404, "body": "nf"}
    _db(tmp_path, monkeypatch)
    assert discover_api_endpoints("a", [], _Empty(), "https://t/", {}, log=lambda m: None) == 0
