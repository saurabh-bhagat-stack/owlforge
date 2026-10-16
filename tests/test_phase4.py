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


def test_render_inventory_annotates_classes_and_interest_and_orders():
    from owlforge.engine.recon import render_inventory

    inv = [
        {"url": "https://t/about", "method": "GET", "params": [], "source": "link"},
        {"url": "https://t/catalog", "method": "GET", "params": ["category"], "source": "html"},
        {"url": "https://t/admin", "method": "GET", "params": [], "source": "content-discovery"},
    ]
    out = render_inventory(inv)
    lines = out.splitlines()
    assert "classes: sqli, xss" in out
    assert "!HIGH" in out
    assert "/catalog" in lines[0]
    assert "/admin" in lines[1]
    assert "/about" in lines[2]


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


def test_api_spec_discovery_parses_openapi(monkeypatch):
    import json

    from owlforge.engine.recon import api_spec_discovery

    spec = {"paths": {
        "/api/users/{id}": {"get": {"parameters": [{"name": "id"}, {"name": "expand"}]},
                             "delete": {}},
        "/api/search": {"get": {"parameters": [{"name": "q"}]}},
    }}

    def fake(method, url, headers=None, params=None, body=None):
        if url.endswith("/openapi.json"):
            return {"status": 200, "body": json.dumps(spec), "headers": {}}
        return {"status": 404, "body": "", "headers": {}}

    out = api_spec_discovery("https://t.test/", fake)
    urls = {(o["method"], o["url"], tuple(o["params"])) for o in out}
    assert ("GET", "https://t.test/api/users", ("expand", "id")) in urls
    assert ("GET", "https://t.test/api/search", ("q",)) in urls
    assert any(m == "DELETE" for m, _, _ in urls)


def test_finish_guard_detects_unfiled_vuln_claim():
    from owlforge.engine.agent import _claims_unfiled_vuln

    # the real GLM miss: it proved SQLi in a note but finished without create_finding
    assert _claims_unfiled_vuln(
        ["Confirmed SQL injection on GET /catalog?category= parameter"],
        "Found SQL injection on category",
    ) is True
    # affirmative phrasings
    assert _claims_unfiled_vuln(["the endpoint is vulnerable to XSS"], "") is True
    # negatives must NOT trigger a nudge
    assert _claims_unfiled_vuln(["No IDOR vulnerability - access restricted"], "") is False
    assert _claims_unfiled_vuln(["could not confirm any vulnerability"], "") is False
    assert _claims_unfiled_vuln([], "") is False


def test_discover_credentials_finds_bearer_without_leaking_value():
    from owlforge.engine.recon import discover_credentials

    def reqfn(method, url, headers=None, params=None, body=None):
        if url.endswith("/static/app.js"):
            return {"status": 200, "body": 'const h={Authorization:"Bearer abcdefghij0123456789XYZ"};'}
        return {"status": 404, "body": ""}

    inv = [{"url": "https://t/static/app.js", "method": "GET", "params": [], "source": "js"}]
    headers, prov = discover_credentials("https://t/", inv, None, reqfn)
    assert headers.get("Authorization", "").startswith("Bearer ")
    assert "abcdefghij0123456789XYZ" in headers["Authorization"]
    # provenance names WHERE, never the secret value
    assert "app.js" in prov and "abcdefghij0123456789XYZ" not in prov


def test_discover_credentials_empty_when_nothing_exposed():
    from owlforge.engine.recon import discover_credentials

    def reqfn(method, url, headers=None, params=None, body=None):
        return {"status": 404, "body": ""}

    headers, prov = discover_credentials("https://t/", [], None, reqfn)
    assert headers == {} and prov == ""


def test_js_endpoint_extraction_covers_fetch_axios_xhr_template_absolute():
    from owlforge.engine.recon import extract_js_endpoints

    js = (
        'fetch("/api/users?role=admin").then(r=>r.json());'
        'axios.post("/api/orders", body);'
        'var x=new XMLHttpRequest(); x.open("GET","/rest/products/list");'
        'const u = `${base}/api/account/${id}/profile`;'
        '$.get("https://api.example.com/v1/search?q="+t);'
        'img.src="/static/logo.png";'
    )
    eps, loose = extract_js_endpoints("https://ui.example.com", js)
    urls = {(e["method"], e["url"]) for e in eps}
    assert ("GET", "https://ui.example.com/api/users") in urls
    assert ("POST", "https://ui.example.com/api/orders") in urls
    assert ("GET", "https://ui.example.com/rest/products/list") in urls
    assert ("GET", "https://ui.example.com/api/account") in urls          # from template literal
    assert ("GET", "https://api.example.com/v1/search") in urls           # cross-origin API host
    assert not any(e["url"].endswith("/static/logo.png") for e in eps)    # assets skipped
    users = next(e for e in eps if e["url"].endswith("/api/users"))
    assert "role" in users["params"]
    assert "role" in loose and "q" in loose
