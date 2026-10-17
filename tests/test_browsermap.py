"""Interactive browser recon (SPA map) -> surface-item conversion (offline)."""

from __future__ import annotations

from owlforge.engine.recon import browser_map


class _SB:
    def __init__(self, resp):
        self._resp = resp
        self.called_with = None

    def map(self, url, *, headers=None, max_pages=12, max_clicks=10, timeout_ms=20_000):
        self.called_with = (url, headers)
        return self._resp


def test_browser_map_converts_xhr_forms_links():
    resp = {
        "pages": [{"url": "https://app.t/", "title": "Home"},
                  {"url": "https://app.t/dashboard", "title": "Dash"}],
        "requests": [
            {"method": "GET", "url": "https://app.t/api/users?role=admin", "type": "xhr"},
            {"method": "POST", "url": "https://app.t/api/search", "type": "fetch"},
            {"method": "GET", "url": "https://app.t/dashboard", "type": "document"},
        ],
        "forms": [{"action": "https://app.t/comment", "method": "POST",
                   "fields": [{"name": "body", "type": "textarea"},
                              {"name": "csrf", "type": "hidden"}]}],
        "links": ["https://app.t/profile?id=7"],
        "websockets": ["wss://app.t/live"],
    }
    sb = _SB(resp)
    out = browser_map("https://app.t/", sb, session_headers={"Cookie": "s=1"})
    by = {(i["method"], i["url"]): i for i in out}

    # XHR/fetch become surface with params extracted and the browser-xhr source
    assert ("GET", "https://app.t/api/users") in by
    assert by[("GET", "https://app.t/api/users")]["params"] == ["role"]
    assert by[("GET", "https://app.t/api/users")]["source"] == "browser-xhr"
    assert ("POST", "https://app.t/api/search") in by

    # document request -> browser-nav
    assert by[("GET", "https://app.t/dashboard")]["source"] == "browser-nav"

    # form fields become params
    assert ("POST", "https://app.t/comment") in by
    assert set(by[("POST", "https://app.t/comment")]["params"]) == {"body", "csrf"}

    # auth session was forwarded to the browser
    assert sb.called_with[1] == {"Cookie": "s=1"}


def test_browser_map_noop_without_sandbox():
    assert browser_map("https://t/", None) == []


def test_browser_map_handles_error_payload():
    sb = _SB({"error": "Timeout", "requests": []})
    assert browser_map("https://t/", sb) == []
