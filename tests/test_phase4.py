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


def test_recon_extracts_params_and_forms_same_origin_only():
    from owlforge.engine.recon import _dedup, extract_surface, render_inventory

    html = (
        '<a href="/catalog?category=Gifts">g</a>'
        '<a href="/catalog?category=Pets">p</a>'
        '<a href="/product?productId=3">x</a>'
        '<a href="https://evil.com/leak">ext</a>'
        '<form action="/login" method="POST"><input name="username"><input name="password"></form>'
    )
    items = _dedup(extract_surface("https://t.test/", html))
    urls = {(i["method"], i["url"], tuple(i["params"])) for i in items}
    assert ("GET", "https://t.test/catalog", ("category",)) in urls      # the breadth fix
    assert ("GET", "https://t.test/product", ("productId",)) in urls
    assert ("POST", "https://t.test/login", ("password", "username")) in urls
    assert not any("evil.com" in i["url"] for i in items)                # same-origin only
    assert "category" in render_inventory(items)


def test_orchestrator_plans_tasks_from_surface():
    from owlforge.engine.classify import OBJECT_ID, PATH, SQLI, SSRF, XSS, classify_param
    from owlforge.engine.orchestrator import plan_tasks

    # param classification
    assert {SQLI, XSS} <= classify_param("searchTerm")
    assert OBJECT_ID in classify_param("productId")
    assert SSRF in classify_param("redirectUrl")
    assert PATH in classify_param("file")

    inv = [
        {"url": "https://t/catalog", "method": "GET", "params": ["category"], "source": "link"},
        {"url": "https://t/product", "method": "GET", "params": ["productId"], "source": "link"},
        {"url": "https://t/admin", "method": "GET", "params": [], "source": "content-discovery"},
    ]
    tasks = plan_tasks(inv)
    # category -> sqli+xss ; productId -> sqli+xss+access_control ; /admin (no params, interesting) -> access_control
    assert any(t["param"] == "category" for t in tasks[SQLI])
    assert any(t["param"] == "productId" for t in tasks[OBJECT_ID])
    assert any(t["url"].endswith("/admin") and t["param"] is None for t in tasks[OBJECT_ID])


def test_orchestrator_prioritizes_free_text_params_for_sqli():
    from owlforge.engine.classify import OBJECT_ID, SQLI
    from owlforge.engine.orchestrator import _priority

    # free-text/filter param ranks above an id for injection
    assert _priority(SQLI, {"url": "https://t/catalog", "param": "category"}) > \
           _priority(SQLI, {"url": "https://t/product", "param": "productId"})
    # hidden admin endpoint ranks high for access control
    assert _priority(OBJECT_ID, {"url": "https://t/admin/users", "param": None}) == 3


def test_recon_captures_param_links_not_in_href():
    from owlforge.engine.recon import _dedup, extract_surface

    # category appears as a /path?query string NOT inside an <a href> (JS/data-built)
    html = '<div data-url="/catalog?category=Gifts"></div><script>var u="/catalog?category=Pets"</script>'
    items = _dedup(extract_surface("https://t.test/catalog", html))
    assert any(i["url"] == "https://t.test/catalog" and "category" in i["params"] for i in items)
