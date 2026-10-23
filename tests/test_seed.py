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


# ---- #4 seeding depth -------------------------------------------------------------------
class _MultiSB:
    """Routes GET/POST per URL with a small handler map for multi-step flows."""

    def __init__(self, handler):
        self._h = handler
        self.posted = []

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if method != "GET":
            self.posted.append((url, method, dict(headers or {}), body))
        return self._h(method, url, headers, body)


_LOGIN_HTML = ('<form action="/login" method=post>'
               '<input name="email"><input type=password name="password"></form>')


def test_register_two_step_login():
    """Sign-up gives no session, but logging in with the new creds does."""
    inv = [
        {"url": "https://t/register", "method": "POST", "source": "form",
         "params": ["email", "username", "password", "confirm_password"]},
        {"url": "https://t/login", "method": "POST", "source": "form",
         "params": ["email", "password"]},
    ]

    def h(method, url, headers, body):
        if url.endswith("/register") and method == "GET":
            return {"status": 200, "headers": {}, "body": _REG_HTML}
        if url.endswith("/register") and method == "POST":
            return {"status": 302, "headers": {"location": "/login"}, "set_cookie": [], "body": ""}
        if url.endswith("/login") and method == "GET":
            return {"status": 200, "headers": {}, "body": _LOGIN_HTML}
        if url.endswith("/login") and method == "POST":
            return {"status": 302, "headers": {"location": "/dashboard"},
                    "set_cookie": ["session=two7; Path=/"], "body": ""}
        return {"status": 404, "headers": {}, "body": ""}

    ident = register_account(inv, _MultiSB(h), "https://t")
    assert ident is not None
    assert ident["headers"]["Cookie"].startswith("session=two7")


def test_seed_json_api_create():
    """A JSON API create captures the id returned in the JSON body."""
    inv = [{"url": "https://t/api/posts", "method": "POST", "source": "api-spec",
            "params": ["title", "body"]}]

    def h(method, url, headers, body):
        if method == "POST" and url.endswith("/api/posts"):
            assert "application/json" in (headers or {}).get("Content-Type", "")
            return {"status": 201, "headers": {}, "body": '{"id": 77, "title": "x"}'}
        return {"status": 404, "headers": {}, "body": ""}

    out = seed_objects(inv, _MultiSB(h), {"Cookie": "s=1"}, "https://t")
    assert len(out) == 1
    assert out[0]["url"] == "https://t/api/posts/77" and out[0]["source"] == "seeded"


def test_seed_multipart_upload_create():
    """A create form with a file input is submitted as multipart and the object captured."""
    upload_html = ('<form action="/files/upload" method=post enctype="multipart/form-data">'
                   '<input name="title"><input type=file name="document"></form>')
    inv = [{"url": "https://t/files/upload", "method": "POST", "source": "form",
            "params": ["title"]}]

    sent = {}

    def h(method, url, headers, body):
        if url.endswith("/files/upload") and method == "GET":
            return {"status": 200, "headers": {}, "body": upload_html}
        if url.endswith("/files/upload") and method == "POST":
            sent["ct"] = (headers or {}).get("Content-Type", "")
            sent["body"] = body
            return {"status": 302, "headers": {"location": "/files/9"}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}

    out = seed_objects(inv, _MultiSB(h), {"Cookie": "s=1"}, "https://t")
    assert len(out) == 1 and out[0]["url"] == "https://t/files/9"
    assert "multipart/form-data" in sent["ct"]
    assert 'filename="owl' in sent["body"] and 'name="document"' in sent["body"]


def test_form_fields_unquoted_and_single_quoted_attrs():
    """Real-world HTML uses unquoted and single-quoted attributes, not only double quotes."""
    html = ("<form action=/posts/create method=post>"
            "<input name=title value=''>"
            "<input name='body' value='v'>"
            '<input type=hidden name="csrf" value="T"></form>')
    f = _form_fields(html, "/posts/create")
    assert "title" in f and "body" in f and "csrf" in f
    assert f["body"] == "v"


def test_register_account_with_unquoted_html():
    """Registration must still be detected when the form uses unquoted attributes."""
    reg = ("<form action=/register method=post>"
           "<input name=email><input type=password name=password>"
           "<input type=password name=confirm_password></form>")
    inv = [{"url": "https://t/register", "method": "POST", "source": "form",
            "params": ["email", "password", "confirm_password"]}]
    sb = _SB(reg, {"status": 302, "headers": {"location": "/home"},
                   "set_cookie": ["session=uq9; Path=/"], "body": ""})
    ident = register_account(inv, sb, "https://t")
    assert ident is not None and ident["headers"]["Cookie"].startswith("session=uq9")
    assert "example.test" in sb.posted[0][1]


# ---- GraphQL mutation seeding -----------------------------------------------------------
class _GqlApp:
    """Introspection-on GraphQL endpoint with a scalar-arg createPost mutation."""

    def __init__(self, introspection=True):
        self.intro = introspection

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        import json as _j
        q = (_j.loads(body or "{}").get("query", "") if body else "")
        if "__schema" in q:
            if not self.intro:
                return {"status": 200, "headers": {}, "body": '{"errors":[{"message":"off"}]}'}
            schema = {"data": {"__schema": {"mutationType": {"fields": [
                {"name": "createPost", "args": [
                    {"name": "title", "type": {"kind": "NON_NULL", "name": None,
                     "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}}]}]}}}}
            return {"status": 200, "headers": {}, "body": _j.dumps(schema)}
        if "createPost" in q:
            return {"status": 200, "headers": {}, "body": '{"data":{"createPost":{"id":"7"}}}'}
        return {"status": 400, "headers": {}, "body": "{}"}


_GQL_INV = [{"url": "https://t/graphql", "method": "POST", "source": "graphql", "params": []}]


def test_graphql_seed_creates_and_captures_id():
    from owlforge.engine.seed import graphql_seed_objects
    out = graphql_seed_objects(_GQL_INV, _GqlApp(), {"Cookie": "s=1"}, "https://t")
    assert len(out) == 1
    assert out[0]["object_id"] == "7" and out[0]["source"] == "seeded-graphql"
    assert out[0]["graphql"] == "mutation createPost"


def test_graphql_seed_quiet_without_introspection():
    from owlforge.engine.seed import graphql_seed_objects
    assert graphql_seed_objects(_GQL_INV, _GqlApp(introspection=False), {"Cookie": "s=1"}, "https://t") == []


def test_graphql_seed_requires_session():
    from owlforge.engine.seed import graphql_seed_objects
    assert graphql_seed_objects(_GQL_INV, _GqlApp(), {}, "https://t") == []


class _GqlInputApp:
    """GraphQL createPost(input: PostInput!) where PostInput has scalar fields."""

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        import json as _j
        q = (_j.loads(body or "{}").get("query", "") if body else "")
        if "__schema" in q:
            return {"status": 200, "headers": {}, "body": _j.dumps({"data": {"__schema": {
                "mutationType": {"fields": [{"name": "createPost", "args": [
                    {"name": "input", "type": {"kind": "NON_NULL", "name": None, "ofType":
                     {"kind": "INPUT_OBJECT", "name": "PostInput", "ofType": None}}}]}]}}}})}
        if "__type" in q and "PostInput" in q:
            return {"status": 200, "headers": {}, "body": _j.dumps({"data": {"__type": {
                "inputFields": [
                    {"name": "title", "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                    {"name": "role", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]}}})}
        if "createPost" in q:
            return {"status": 200, "headers": {}, "body": '{"data":{"createPost":{"id":"9"}}}'}
        return {"status": 400, "headers": {}, "body": "{}"}


def test_graphql_seed_input_object_mutation():
    from owlforge.engine.seed import graphql_seed_objects
    out = graphql_seed_objects(_GQL_INV, _GqlInputApp(), {"Cookie": "s=1"}, "https://t")
    assert len(out) == 1
    assert out[0]["object_id"] == "9" and out[0]["read_field"] == "post"


class _SpaSB:
    """Raw GET returns an empty SPA shell (no form); the form only exists in the rendered DOM."""

    def __init__(self, post_resp):
        self._post = post_resp
        self.posted = []

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if method == "GET":
            return {"status": 200, "headers": {}, "body": "<div id='app'></div>"}
        self.posted.append((url, body))
        return dict(self._post)

    def render(self, url, *, headers=None, timeout_ms=30000):
        return {"html": _REG_HTML, "final_url": url}


def test_register_uses_rendered_dom_for_js_form():
    inv = [{"url": "https://t/register", "method": "POST", "source": "form",
            "params": ["email", "username", "password", "confirm_password"]}]
    sb = _SpaSB({"status": 302, "headers": {"location": "/home"},
                 "set_cookie": ["session=spa1; Path=/"], "body": ""})
    ident = register_account(inv, sb, "https://t")
    assert ident is not None and ident["headers"]["Cookie"].startswith("session=spa1")
    assert sb.posted and "example.test" in sb.posted[0][1]
