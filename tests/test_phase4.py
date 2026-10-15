"""Phase 4: auth context (unauth / session / login) + session-header injection."""

from __future__ import annotations

from owlforge.engine.auth import AuthContext, _parse_set_cookie, establish_session


def test_unauth_and_session_modes():
    assert establish_session(AuthContext(), lambda *a, **k: {}) == {}
    sess = establish_session(
        AuthContext(mode="session", headers={"Cookie": "s=abc", "X-API": "k"}), lambda *a, **k: {}
    )
    assert sess == {"Cookie": "s=abc", "X-API": "k"}


def test_login_mode_captures_cookie_and_checks_success():
    calls = {}

    def fake(method, url, headers=None, params=None, body=None):
        calls["method"], calls["url"], calls["body"] = method, url, body
        return {"status": 302, "headers": {"Set-Cookie": "session=xyz; Path=/; HttpOnly"}, "body": "Welcome"}

    sess = establish_session(
        AuthContext(mode="login", login_url="https://t/login",
                    login_params={"username": "a", "password": "b"}, login_success="Welcome"),
        fake,
    )
    assert sess.get("Cookie") == "session=xyz"
    assert calls["method"] == "POST" and "username=a" in calls["body"] and "password=b" in calls["body"]


def test_cookie_parse_drops_attributes():
    out = _parse_set_cookie("AWSALB=xx; Expires=Wed, 01 Jan 2030 00:00:00 GMT; Path=/, session=abc; HttpOnly")
    assert "session=abc" in out and "AWSALB=xx" in out and "Expires" not in out and "Path" not in out


def test_toolcontext_has_session_headers():
    from owlforge.tools.base import ToolContext

    ctx = ToolContext(assessment_id="a", target="t", emit=lambda *a, **k: None,
                      session_headers={"Cookie": "s=1"})
    assert ctx.session_headers == {"Cookie": "s=1"}
