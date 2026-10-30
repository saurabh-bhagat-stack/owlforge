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


class _HeaderGatedApp:
    """GET /login hides X-Dev-Access in a ROT13 comment; POST /login authenticates ONLY when
    both the X-Dev-Access: yes header AND a NoSQL operator payload are present (Crack-the-Gate)."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        import codecs
        import urllib.parse as _up
        if _up.urlsplit(url).path == "/login" and method == "GET":
            rot = codecs.encode("X-Dev-Access: yes", "rot_13")
            return {"status": 200, "body": f"<html><!-- note: {rot} --></html>"}
        if _up.urlsplit(url).path == "/login" and method == "POST":
            h = {k.lower(): v for k, v in (headers or {}).items()}
            dev = str(h.get("x-dev-access", "")).lower() == "yes"
            nosql = bool(body) and "$ne" in body
            if dev and nosql:
                return {"status": 200, "body": '{"token":"ey.sessiontoken.abcdefghij"}'}
            return {"status": 401, "body": '{"error":"User not found"}'}
        return {"status": 404, "body": "nf"}


class _PureBackdoorApp:
    """POST /login authenticates on the X-Backdoor: 1 header alone, no credentials."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        import urllib.parse as _up
        if _up.urlsplit(url).path == "/login" and method == "GET":
            return {"status": 200, "body": "<html><!-- use X-Backdoor to get in --></html>"}
        if _up.urlsplit(url).path == "/login" and method == "POST":
            if str({k.lower(): v for k, v in (headers or {}).items()}.get("x-backdoor", "")) == "1":
                return {"status": 200, "body": '{"token":"ey.sessiontoken.abcdefghij"}'}
            return {"status": 401, "body": '{"error":"nope"}'}
        return {"status": 404, "body": "nf"}


_INV_LOGIN = [{"url": "https://t/login", "method": "POST", "params": []}]


def test_header_gated_nosql_bypass_confirmed(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = login_authbypass_scan("a", _INV_LOGIN, _HeaderGatedApp(), "https://t/", {})
    assert n == 1
    f = _findings(db)
    assert len(f) == 1 and f[0].severity == "critical"
    assert "header" in f[0].title.lower()  # header-gated kind in the title


def test_pure_backdoor_header_confirmed(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = login_authbypass_scan("a", _INV_LOGIN, _PureBackdoorApp(), "https://t/", {})
    assert n == 1
    assert "backdoor header" in _findings(db)[0].title.lower()


class _KnownUserApp:
    """Password bypass: the REAL user (victim@site.com) + a non-string password operator ($ne)
    authenticates; a wrong email fails even with the operator, and a generic injection fails."""
    USER = "victim@site.com"

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        import json as _j
        import urllib.parse as _up
        if _up.urlsplit(url).path == "/login" and method == "POST":
            d = _j.loads(body) if body else {}
            if d.get("email") == self.USER and isinstance(d.get("password"), dict):
                return {"status": 200, "body": '{"token":"ey.sessiontoken.abcdefghij"}'}
            return {"status": 401, "body": '{"error":"invalid"}'}
        return {"status": 404, "body": "nf"}


def test_known_user_password_bypass(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = login_authbypass_scan("a", [{"url": "https://t/login", "method": "POST", "params": []}],
                              _KnownUserApp(), "https://t/", {},
                              message="the login email is victim@site.com, password unknown")
    assert n == 1
    assert "known-user" in _findings(db)[0].title.lower()
