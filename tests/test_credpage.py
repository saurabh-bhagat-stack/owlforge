"""Login-page credential harvesting (multi-step, cookie-aware)."""

from __future__ import annotations

from owlforge.engine.credpage import _extract_creds, _extract_form, establish_from_login_page


def test_extract_creds_and_form_unquoted_attrs():
    assert _extract_creds("<span><b>Username</b> carlos</span>") == {"username": "carlos"}
    assert _extract_creds("<b>Password</b> hunter2 Log in").get("password") == "hunter2"
    f = _extract_form('<form action=/login method=POST>'
                      '<input name=csrf value=tok><input name=username>'
                      '<input type=password name=password></form>')
    assert f["action"] == "/login" and f["user_field"] == "username"
    assert f["pass_field"] == "password" and f["csrf_field"] == "csrf"


def test_establish_from_login_page_two_step_cookie_aware():
    """Simulate ginandjuice: /login shows username; after POSTing it the page shows the
    password; a session-bound csrf requires carrying the cookie."""
    def reqfn(method, url, headers=None, params=None, body=None):
        has_cookie = "Cookie" in (headers or {})
        if method == "GET" and url.endswith("/login"):
            return {"status": 200, "headers": {"Set-Cookie": "session=S1; Path=/"},
                    "body": '<form action=/login method=POST><input name=csrf value=T1>'
                            '<input name=username></form><span><b>Username</b> carlos</span>'}
        if method == "POST" and url.endswith("/login"):
            if not has_cookie:
                return {"status": 400, "body": "Missing parameter 'csrf'"}
            if "password" not in (body or ""):   # step: username only -> reveal password page
                return {"status": 200, "body": '<form action=/login method=POST>'
                        '<input name=csrf value=T2><input name=username>'
                        '<input type=password name=password></form><b>Password</b> hunter2'}
            return {"status": 302, "headers": {"Set-Cookie": "session=AUTHED; Path=/"}, "body": ""}
        if method == "GET" and url.endswith("/my-account"):
            return {"status": 200, "body": "Welcome carlos — Log out"}
        return {"status": 404, "body": ""}

    sh, prov = establish_from_login_page("https://t/", None, reqfn)
    assert sh.get("Cookie") and "AUTHED" in sh["Cookie"]
    assert "carlos" in prov
