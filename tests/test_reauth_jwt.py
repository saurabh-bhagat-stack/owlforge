"""Mid-scan reauth: JWT/SPA sessions refresh via the browser; login endpoints don't trigger it."""
from __future__ import annotations

from owlforge.engine.reauth import ReauthSandbox

# a valid-shaped JWT kept in localStorage (becomes Authorization: Bearer on refresh)
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.abcDEFghiJKLmnoPQRstuVWxyz012345"
_SPEC = {"browser_url": "https://t/#/login", "user": "u", "password": "p",
         "user_field": None, "pass_field": None}


class _Inner:
    """Authed request with the OLD session fails; a browser re-login yields a FRESH session."""

    def __init__(self):
        self.browser_calls = 0

    def browser_login(self, url, username, password, *, user_field=None, pass_field=None,
                      headers=None, check_url=None, success=None):
        self.browser_calls += 1
        return {"storage_state": {"cookies": [{"name": "sid", "value": "FRESH", "domain": "t",
                                               "path": "/"}],
                                  "origins": [{"origin": "https://t",
                                               "localStorage": [{"name": "token", "value": _JWT}]}]},
                "success": True, "logged_in_hint": True}

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        h = headers or {}
        fresh = "FRESH" in h.get("Cookie", "") or "Bearer" in h.get("Authorization", "")
        return {"status": 200, "body": "ok"} if fresh else {"status": 401, "body": "dead"}


def test_jwt_session_refreshes_through_the_browser():
    sh = {"Cookie": "sid=OLD"}
    inner = _Inner()
    sb = ReauthSandbox(inner, sh, [_SPEC], log=lambda m: None)
    r = sb.http_request("GET", "https://t/account", headers={"Cookie": "sid=OLD"})
    assert r["status"] == 200                         # retried after a browser re-login
    assert inner.browser_calls == 1
    assert ("FRESH" in sh.get("Cookie", "")) or ("Authorization" in sh)   # updated in place


def test_login_endpoint_401_does_not_trigger_reauth():
    inner = _Inner()
    sb = ReauthSandbox(inner, {"Cookie": "sid=OLD"}, [_SPEC], log=lambda m: None)
    r = sb.http_request("POST", "https://t/rest/user/login", headers={"Cookie": "sid=OLD"})
    assert r["status"] == 401                         # a failed login is not a dead session
    assert inner.browser_calls == 0


def test_http_fallback_when_no_browser_login():
    # inner without browser_login → _browser_refresh is skipped; HTTP reauth_login path is used.
    class _HttpOnly:
        def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
            return {"status": 401, "body": "dead"}
    sb = ReauthSandbox(_HttpOnly(), {"Cookie": "sid=OLD"}, [{"url": "https://t/login",
                       "data": "username=u&password=p", "success": ""}], log=lambda m: None)
    # should not raise; reauth simply fails (login also 401) and the original response returns
    r = sb.http_request("GET", "https://t/account", headers={"Cookie": "sid=OLD"})
    assert r["status"] == 401
