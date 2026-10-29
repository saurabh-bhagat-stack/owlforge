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


_INV = [{"url": "https://t/rest/user/login", "method": "POST", "params": []}]


class _LoginApi:
    """JSON login: returns a token ONLY when the body carries an injection payload."""

    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if "/rest/user/login" in url and method == "POST":
            b = body or ""
            inj = any(m in b for m in ("OR 1=1", "'1'='1", "$ne", "$gt", "admin'"))
            if self.vulnerable and inj:
                return {"status": 200, "headers": {"content-type": "application/json"},
                        "body": '{"authentication":{"token":"ey.sessiontoken.abcdefghijkl"}}'}
            return {"status": 401, "headers": {}, "body": '{"error":"Invalid email or password"}'}
        return {"status": 404, "headers": {}, "body": ""}       # no HTML login form exists


def test_auth_signal_detects_token_and_cookie_not_loginpage():
    assert "token" in _auth_signal({"status": 200, "body": '{"token":"abcdefghijklmnop"}'})
    assert "session-cookie" in _auth_signal(
        {"status": 200, "headers": {"set-cookie": "connect.sid=s%3Aabcdef12345; Path=/"}, "body": ""})
    # a login page / error is NOT an auth signal
    assert _auth_signal({"status": 200, "body": '<input type="password" name="password">'}) == set()
    assert _auth_signal({"status": 401, "body": "invalid password"}) == set()


def test_login_targets_picks_api_login_endpoint():
    ts = _login_targets(_INV, None)
    assert any(t["url"].endswith("/rest/user/login") and t["kind"] == "api" for t in ts)


def test_bypass_filed_when_payload_authenticates(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = login_authbypass_scan("a", _INV, _LoginApi(vulnerable=True), "https://t/", {})
    assert n == 1
    f = _findings(db)
    assert len(f) == 1
    assert "Authentication bypass" in f[0].title
    assert f[0].severity == "critical" and f[0].status == "validated"


def test_no_finding_when_login_is_safe(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = login_authbypass_scan("a", _INV, _LoginApi(vulnerable=False), "https://t/", {})
    assert n == 0
    assert _findings(db) == []
