"""SSO breadth: provider detection + OAuth2 authorization-request misconfig."""
from __future__ import annotations

from urllib.parse import urlsplit


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


def test_detect_sso_providers():
    from owlforge.engine.sso import detect_sso
    assert detect_sso('<a href="/auth/google">Sign in with Google</a>') == ["Google"]
    assert "Okta" in detect_sso('<script src="https://acme.okta.com/x"></script>')
    assert "SAML" in detect_sso('<form action="/saml2/acs"><input name="SAMLRequest="></form>')
    assert detect_sso("<form><input name=user><input type=password name=pw></form>") == []


def test_oauth_issues_pure():
    from owlforge.engine.sso import oauth_issues
    assert dict(oauth_issues("https://idp/authorize?client_id=x&response_type=code&redirect_uri=y")) \
        .get("missing_state")
    assert dict(oauth_issues("https://idp/authorize?response_type=token&state=s")).get("implicit")
    assert oauth_issues("https://idp/authorize?response_type=code&state=s&client_id=x") == []
    assert oauth_issues("https://app/login") == []   # not an authorization request


class _SsoApp:
    def __init__(self, with_state=False, response_type="code"):
        self.with_state = with_state
        self.rt = response_type

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        path = urlsplit(url).path
        if path in ("", "/"):
            return {"status": 200, "headers": {}, "body": "<html>home</html>"}
        if path == "/login":
            return {"status": 200, "headers": {},
                    "body": '<a href="/auth/google">Sign in with Google</a>'}
        if path == "/auth/google":
            auth = ("https://accounts.google.com/o/oauth2/v2/auth?client_id=x"
                    f"&redirect_uri=https://app.local/cb&response_type={self.rt}")
            if self.with_state:
                auth += "&state=abc123"
            return {"status": 302, "headers": {"location": auth}, "body": ""}
        return {"status": 404, "headers": {}, "body": "nf"}


INV = [{"url": "https://app.local/login", "method": "GET", "source": "link"}]


def test_sso_scan_flags_missing_state(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.sso import sso_scan
    n = sso_scan("a", INV, _SsoApp(with_state=False), "https://app.local")
    assert n >= 1
    assert any("state" in f.title.lower() and f.status == "candidate" for f in _findings(db))


def test_sso_scan_flags_implicit_flow(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.sso import sso_scan
    n = sso_scan("a", INV, _SsoApp(with_state=True, response_type="token"), "https://app.local")
    assert n >= 1
    assert any("implicit flow" in f.title.lower() for f in _findings(db))


def test_sso_scan_quiet_when_well_configured(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.sso import sso_scan
    assert sso_scan("a", INV, _SsoApp(with_state=True, response_type="code"), "https://app.local") == 0
    assert _findings(db) == []
