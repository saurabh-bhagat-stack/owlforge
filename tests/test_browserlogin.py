"""Browser-driven login + model-assisted label-free credential extraction."""
from __future__ import annotations

TARGET = "https://app.local"
_STATE = {"cookies": [{"name": "session", "value": "abc123", "domain": "app.local"}],
          "origins": []}


class _LoginSB:
    """A sandbox exposing browser_login; `ok` toggles a successful capture."""

    def __init__(self, ok=True, hint=True, success=None, err=None):
        self.ok, self.hint, self.success, self.err = ok, hint, success, err
        self.called_with = None

    def browser_login(self, url, username, password, *, user_field=None, pass_field=None,
                      headers=None, check_url=None, success=None, timeout_ms=30000):
        self.called_with = (url, username, password)
        if self.err:
            return {"error": self.err}
        state = _STATE if self.ok else {"cookies": [], "origins": []}
        return {"storage_state": state, "final_url": url,
                "logged_in_hint": self.hint, "success": self.success}


class _NoLoginSB:
    """Old sandbox image — no browser_login attribute."""


def test_browser_login_captures_session():
    from owlforge.engine.browserlogin import browser_login_session
    sb = _LoginSB(ok=True, hint=True)
    hdrs, confirmed = browser_login_session(sb, f"{TARGET}/login", "alice", "pw", TARGET)
    assert hdrs.get("Cookie", "").startswith("session=abc123") and confirmed
    assert sb.called_with == (f"{TARGET}/login", "alice", "pw")


def test_browser_login_falls_back_when_unavailable():
    from owlforge.engine.browserlogin import browser_login_session
    assert browser_login_session(_NoLoginSB(), f"{TARGET}/login", "a", "b", TARGET) == ({}, False)
    assert browser_login_session(None, f"{TARGET}/login", "a", "b", TARGET) == ({}, False)


def test_browser_login_error_is_fallback():
    from owlforge.engine.browserlogin import browser_login_session
    assert browser_login_session(_LoginSB(err="boom"), f"{TARGET}/login", "a", "b", TARGET) == ({}, False)


def test_browser_login_rejects_explicit_failed_success():
    from owlforge.engine.browserlogin import browser_login_session
    sb = _LoginSB(ok=True, hint=False, success=False)   # success string checked and NOT found
    assert browser_login_session(sb, f"{TARGET}/login", "a", "b", TARGET, success="Welcome") == ({}, False)


# ---- label-free credential extraction (model) -------------------------------------------
class _Turn:
    def __init__(self, content):
        self.content = content


class _FakeClient:
    def __init__(self, content):
        self._c = content

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None):
        return _Turn(self._c)


def test_extract_credentials_label_free():
    from owlforge.engine.browserlogin import extract_displayed_credentials
    # creds shown with NO 'username:'/'password:' labels — the model returns the pair
    client = _FakeClient('Here: [{"username": "wiener", "password": "peter"}]')
    out = extract_displayed_credentials(client, "<div>Try wiener / peter</div>")
    assert out == [{"username": "wiener", "password": "peter"}]


def test_extract_credentials_none_shown():
    from owlforge.engine.browserlogin import extract_displayed_credentials
    assert extract_displayed_credentials(_FakeClient("[]"), "<form>...</form>") == []
    assert extract_displayed_credentials(_FakeClient("no json here"), "x") == []
    assert extract_displayed_credentials(None, "x") == []
