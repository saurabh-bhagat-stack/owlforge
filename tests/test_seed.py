"""Stateful seeding: register a throwaway account + create marker objects."""
from __future__ import annotations

from owlforge.engine.seed import _fill, _form_fields, register_account, seed_objects

_REG_HTML = ('<form action="/register" method=post>'
             '<input type=hidden name="csrf" value="T">'
             '<input name="email"><input name="username">'
             '<input type=password name="password">'
             '<input type=password name="confirm_password"></form>')
_CREATE_HTML = ('<form action="/posts/create" method=post>'
                '<input type=hidden name="csrf" value="T">'
                '<input name="title"><textarea name="body"></textarea></form>')


class _SB:
    """GET returns a page; POST returns a configured response (and records the body)."""

    def __init__(self, get_html, post_resp):
        self._html = get_html
        self._post = post_resp
        self.posted = []

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if method == "GET":
            return {"status": 200, "headers": {}, "body": self._html}
        self.posted.append((url, body))
        return dict(self._post)


def test_fill_values():
    assert _fill("email", "owlx") == "owlx@example.test"
    assert _fill("password", "owlx").startswith("Owl_")
    assert _fill("title", "owlx").startswith("owlforge test")


def test_form_fields_parsing():
    f = _form_fields(_CREATE_HTML, "/posts/create")
    assert "title" in f and "body" in f and "csrf" in f


def test_register_account_auto_session():
    inv = [{"url": "https://t/register", "method": "POST", "source": "form",
            "params": ["email", "username", "password", "confirm_password"]}]
    sb = _SB(_REG_HTML, {"status": 302, "headers": {"location": "/dashboard"},
                         "set_cookie": ["session=abc123; Path=/; HttpOnly"], "body": ""})
    ident = register_account(inv, sb, "https://t")
    assert ident is not None
    assert ident["headers"]["Cookie"].startswith("session=abc123")
    # a real register POST was sent with a marker email, not blank
    assert sb.posted and "example.test" in sb.posted[0][1]


def test_register_no_session_returns_none():
    inv = [{"url": "https://t/register", "method": "POST", "source": "form",
            "params": ["email", "password", "confirm_password"]}]
    sb = _SB(_REG_HTML, {"status": 302, "headers": {"location": "/login"}, "set_cookie": [], "body": ""})
    assert register_account(inv, sb, "https://t") is None   # no auto-session -> not returned


def test_seed_objects_captures_created_id():
    inv = [{"url": "https://t/posts/create", "method": "POST", "source": "form",
            "params": ["title", "body"]}]
    sb = _SB(_CREATE_HTML, {"status": 302, "headers": {"location": "/posts/42"},
                            "set_cookie": [], "body": ""})
    out = seed_objects(inv, sb, {"Cookie": "session=x"}, "https://t")
    assert len(out) == 1
    assert out[0]["url"] == "https://t/posts/42" and out[0]["source"] == "seeded"
    assert "owlforge+test" in sb.posted[0][1]      # marker body was posted


def test_seed_requires_session():
    inv = [{"url": "https://t/posts/create", "method": "POST", "source": "form", "params": ["title"]}]
    assert seed_objects(inv, _SB(_CREATE_HTML, {}), {}, "https://t") == []
    assert seed_objects(inv, None, {"Cookie": "x"}, "https://t") == []
