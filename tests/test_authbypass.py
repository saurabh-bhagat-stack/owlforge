"""Login auth-bypass probe: SQL/NoSQL payloads that flip a failed login into an authed one."""
from __future__ import annotations

from owlforge.engine.authbypass import _auth_signal, _login_targets, login_authbypass_scan


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
        return list(s.exec(select(Finding)))


class _JuiceLike:
    """SPA: /login, /signin, /session serve the HTML shell; the real login is the JSON API
    POST /rest/user/login (which the crawler never recorded)."""
    SHELL = "<!doctype html><html><app-root></app-root></html>"

    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        bare = url.rstrip("/")
        if bare.endswith("/rest/user/login") and method == "POST":
            inj = any(m in (body or "") for m in ("OR 1=1", "'1'='1", "$ne", "$gt", "admin'"))
            if self.vulnerable and inj:
                return {"status": 200, "headers": {"content-type": "application/json"},
                        "body": '{"authentication":{"token":"ey.sessiontoken.abcdefghijkl"}}'}
            return {"status": 401, "headers": {}, "body": '{"error":"Invalid email or password"}'}
        if any(bare.endswith(p) for p in ("/login", "/signin", "/session", "/sign-in")):
            return {"status": 200, "headers": {}, "body": self.SHELL}       # SPA shell route
        return {"status": 404, "headers": {}, "body": "not found"}


def test_auth_signal_detects_token_and_cookie_not_loginpage():
    assert "token" in _auth_signal({"status": 200, "body": '{"token":"abcdefghijklmnop"}'})
    assert "session-cookie" in _auth_signal(
        {"status": 200, "headers": {"set-cookie": "connect.sid=s%3Aabcdef12345; Path=/"}, "body": ""})
    assert _auth_signal({"status": 200, "body": '<input type="password" name="password">'}) == set()
    assert _auth_signal({"status": 401, "body": "invalid password"}) == set()


def test_login_targets_injects_known_api_paths_from_target():
    urls = [t["url"] for t in _login_targets([], None, "https://t/")]
    assert "https://t/rest/user/login" in urls          # real login API, never crawled
    assert "https://t/api/auth/login" in urls


def test_bypass_found_on_json_api_even_when_only_spa_routes_were_crawled(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    # inventory only has SPA shell routes; the real /rest/user/login comes from the known-paths list
    inv = [{"url": "https://t/login", "method": "POST", "params": []},
           {"url": "https://t/signin", "method": "POST", "params": []}]
    n = login_authbypass_scan("a", inv, _JuiceLike(vulnerable=True), "https://t/", {})
    assert n == 1
    f = _findings(db)
    assert len(f) == 1
    assert "Authentication bypass" in f[0].title and f[0].severity == "critical"
    assert f[0].endpoint.endswith("/rest/user/login")   # shell routes were skipped


def test_no_finding_when_login_is_safe(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = login_authbypass_scan("a", [], _JuiceLike(vulnerable=False), "https://t/", {})
    assert n == 0
    assert _findings(db) == []
