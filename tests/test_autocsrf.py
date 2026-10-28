"""http_request auto-CSRF: a token-missing rejection is transparently fetched + retried."""
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


class _CsrfApp:
    """POST /login needs a session-bound csrf token shown on GET /login."""

    def __init__(self, enforce=True):
        self.enforce = enforce
        self.posts = []

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/login") and method == "GET":
            return {"status": 200, "set_cookie": ["session=S1; Path=/"],
                    "headers": {}, "body": '<form><input name="csrf" value="TOK123"></form>'}
        if url.endswith("/login") and method == "POST":
            self.posts.append(body or "")
            has_tok = "TOK123" in (body or "") and "session=S1" in (headers or {}).get("Cookie", "")
            if self.enforce and not has_tok:
                return {"status": 400, "headers": {}, "body": "Missing parameter 'csrf'"}
            return {"status": 200, "headers": {}, "body": "welcome carlos"}
        return {"status": 404, "headers": {}, "body": ""}


def _ctx(sandbox):
    from owlforge.tools.base import ToolContext
    return ToolContext(assessment_id="a", target="https://t", emit=lambda *a, **k: None,
                       sandbox=sandbox, session_headers={})


def test_auto_csrf_retries_and_succeeds(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.tools.builtin import _http_request
    app = _CsrfApp(enforce=True)
    out = asyncio.run(_http_request(
        {"method": "POST", "url": "https://t/login", "body": "username=carlos&password=x"}, _ctx(app)))
    assert "status=200" in out and "welcome carlos" in out
    # it first tried without the token, then retried with it
    assert any("TOK123" in p for p in app.posts)


def test_no_csrf_no_retry(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.tools.builtin import _http_request
    app = _CsrfApp(enforce=False)
    out = asyncio.run(_http_request(
        {"method": "POST", "url": "https://t/login", "body": "username=carlos&password=x"}, _ctx(app)))
    assert "status=200" in out
    assert len(app.posts) == 1          # no needless retry when it wasn't a CSRF block
