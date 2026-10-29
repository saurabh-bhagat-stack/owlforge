"""`login`-type identities authenticate via the real browser (SPA-aware), HTTP as fallback."""
from __future__ import annotations

from owlforge.engine.identities import Identity, establish_identity


class _BrowserSB:
    """A sandbox whose browser login succeeds and returns a storage_state cookie."""
    def __init__(self):
        self.called = False

    def browser_login(self, url, username, password, *, user_field=None, pass_field=None,
                      headers=None, check_url=None, success=None):
        self.called = True
        return {"storage_state": {"cookies": [{"name": "sess", "value": "BROWSERTOK",
                                               "domain": "t"}]},
                "success": True, "logged_in_hint": True}


def _http_reqfn(method, url, headers=None, params=None, body=None):
    return {"status": 200, "headers": {"Set-Cookie": "sid=HTTPTOK; Path=/"}, "body": "ok"}


def test_login_identity_prefers_browser_when_sandbox_present():
    sb = _BrowserSB()
    ident = Identity(label="carol", auth={"type": "login", "url": "https://t/login",
                                          "data": "username=carol&password=pw"})
    establish_identity(ident, _http_reqfn, sandbox=sb)
    assert sb.called is True
    assert "BROWSERTOK" in ident.session_headers.get("Cookie", "")


def test_login_identity_http_fallback_without_sandbox():
    ident = Identity(label="carol", auth={"type": "login", "url": "https://t/login",
                                          "data": "username=carol&password=pw"})
    establish_identity(ident, _http_reqfn, sandbox=None)
    assert "HTTPTOK" in ident.session_headers.get("Cookie", "")


def test_login_with_totp_stays_on_http_even_with_sandbox():
    # browser login can't carry an OTP field, so a TOTP identity must use the HTTP path
    sb = _BrowserSB()
    ident = Identity(label="carol", auth={"type": "login", "url": "https://t/login",
                                          "data": "username=carol&password=pw",
                                          "totp_secret": "JBSWY3DPEHPK3PXP"})
    establish_identity(ident, _http_reqfn, sandbox=sb)
    assert sb.called is False
    assert "HTTPTOK" in ident.session_headers.get("Cookie", "")
