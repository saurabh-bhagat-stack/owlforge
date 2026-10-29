"""Auth-mechanism detection -> the right operator hint."""
from __future__ import annotations

from urllib.parse import urlsplit

from owlforge.engine.authdetect import detect_auth_mechanism


def _mk(root=None, pages=None):
    pages = pages or {}

    def reqfn(method, url, headers=None, params=None, body=None):
        path = urlsplit(url).path or "/"
        if path in ("", "/"):
            return root or {"status": 200, "body": "home page"}
        return pages.get(path, {"status": 404, "body": ""})
    return reqfn


def test_http_basic():
    rf = _mk(root={"status": 401, "headers": {"WWW-Authenticate": "Basic realm=app"}, "body": ""})
    assert detect_auth_mechanism("https://t/", rf)["mechanism"] == "http-basic"


def test_sso_oauth():
    rf = _mk(pages={"/login": {"status": 200,
             "body": "<a href='https://accounts.google.com/o/oauth2'>Sign in with Google</a>"}})
    m = detect_auth_mechanism("https://t/", rf)
    assert m["mechanism"] == "sso-oauth" and "google" in m["idp"]


def test_form_login():
    rf = _mk(pages={"/login": {"status": 200,
             "body": '<form action=/login method=post><input type="password" name=pw></form>'}})
    assert detect_auth_mechanism("https://t/", rf)["mechanism"] == "form"


def test_token_spa():
    rf = _mk(pages={"/login": {"status": 200,
             "body": "<script>localStorage.setItem('access_token', jwt)</script>"}})
    assert detect_auth_mechanism("https://t/", rf)["mechanism"] == "token-spa"


def test_api_key():
    rf = _mk(root={"status": 401, "body": "Provide a valid API key in X-API-Key"})
    assert detect_auth_mechanism("https://t/", rf)["mechanism"] == "api-key"


def test_unknown():
    rf = _mk(root={"status": 200, "body": "welcome, nothing to log into"})
    assert detect_auth_mechanism("https://t/", rf)["mechanism"] == "unknown"


def test_hint_present_for_each():
    rf = _mk(pages={"/login": {"status": 200, "body": "<form><input type='password'></form>"}})
    assert "--cred" in detect_auth_mechanism("https://t/", rf)["hint"]
