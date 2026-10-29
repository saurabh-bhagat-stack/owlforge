"""Transparent mid-scan re-auth wrapper."""
from __future__ import annotations

from owlforge.engine.reauth import ReauthSandbox

_SPEC = {"url": "https://t/login", "data": "username=u&password=p", "success": ""}


class _Inner:
    """Authed requests with the OLD cookie 401; after a login POST a FRESH cookie works."""
    def __init__(self):
        self.login_posts = 0

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        h = headers or {}
        if url.endswith("/login") and method == "POST":
            self.login_posts += 1
            return {"status": 200, "headers": {"Set-Cookie": "sid=FRESH; Path=/"}, "body": "ok"}
        if "Cookie" in h:
            if "FRESH" in h["Cookie"]:
                return {"status": 200, "body": "authed data"}
            return {"status": 401, "body": "session expired"}
        return {"status": 200, "body": "anon page"}

    def render(self, url, **kw):
        return {"html": "<p>delegated</p>"}


def test_reauths_and_retries_on_dead_session():
    sh = {"Cookie": "sid=OLD"}
    inner = _Inner()
    sb = ReauthSandbox(inner, sh, [_SPEC], log=lambda m: None)
    r = sb.http_request("GET", "https://t/account", headers={"Cookie": "sid=OLD"})
    assert r["status"] == 200 and r["body"] == "authed data"   # retried after reauth
    assert "FRESH" in sh["Cookie"]                              # shared dict updated in place
    assert inner.login_posts == 1


def test_anonymous_request_not_reauthed():
    sh = {"Cookie": "sid=OLD"}
    inner = _Inner()
    sb = ReauthSandbox(inner, sh, [_SPEC], log=lambda m: None)
    r = sb.http_request("GET", "https://t/public", headers=None)
    assert r["body"] == "anon page" and inner.login_posts == 0   # anon probes left alone


def test_delegates_other_methods():
    sb = ReauthSandbox(_Inner(), {"Cookie": "x"}, [_SPEC])
    assert sb.render("https://t/")["html"] == "<p>delegated</p>"
