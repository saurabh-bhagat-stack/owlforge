"""SPA self-registration: create a throwaway account via a JSON API, then log it in."""
from __future__ import annotations

import json

from owlforge.engine.spaseed import _build_object, _value_for, register_json_spa

_SPEC = {
    "openapi": "3.0.0",
    "paths": {"/api/Users": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/New"}}}}}}},
    "components": {"schemas": {"New": {"type": "object",
                   "required": ["email", "password", "nickname", "card"],
                   "properties": {"email": {"type": "string"}, "password": {"type": "string"},
                                  "nickname": {"type": "string"}, "card": {"type": "string"}}}}},
}


class _SpaApp:
    """An SPA that serves an OpenAPI doc, registers via JSON /api/Users (no session on sign-up),
    and issues a token only on a correct JSON login at /rest/user/login."""

    def __init__(self):
        self.users = {}

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith(("/swagger-json", "/openapi.json", "/api-docs")):
            return {"status": 200, "body": json.dumps(_SPEC)}
        if url.endswith("/api/Users") and method == "POST":
            d = json.loads(body) if body else {}
            if d.get("email") and d.get("password"):
                self.users[d["email"]] = d["password"]
                return {"status": 201, "body": json.dumps({"email": d["email"]})}  # no session yet
            return {"status": 400, "body": "bad"}
        if url.endswith("/rest/user/login") and method == "POST":
            d = json.loads(body) if body else {}
            em = d.get("email") or d.get("user")
            if em and self.users.get(em) == d.get("password"):
                return {"status": 200, "body": json.dumps(
                    {"authentication": {"token": "ey.sessiontoken.abcdefghijkl"}})}
            return {"status": 401, "body": "no"}
        return {"status": 404, "body": "nf"}


def test_value_for_by_name_and_type():
    assert _value_for("email", {"type": "string"}, {}, "m", "e@x", "pw") == "e@x"
    assert _value_for("password", {"type": "string"}, {}, "m", "e@x", "pw") == "pw"
    assert _value_for("age", {"type": "integer"}, {}, "m", "e@x", "pw") == 1
    assert _value_for("active", {"type": "boolean"}, {}, "m", "e@x", "pw") is True


def test_build_object_fills_required_from_schema():
    body = _build_object(_SPEC["components"]["schemas"]["New"], _SPEC, "mk", "owl@x", "pw1")
    assert body["email"] == "owl@x" and body["password"] == "pw1"
    assert body["nickname"] and body["card"]            # required fields all present


def test_register_json_spa_registers_then_logs_in():
    app = _SpaApp()
    ident = register_json_spa([], app, "https://t/", log=lambda m: None)
    assert ident is not None
    assert ident["label"] == "owlforge-registered" and ident["role"] == "user"
    assert "Bearer" in ident["headers"].get("Authorization", "")   # logged the new account in
    assert len(app.users) == 1                                     # exactly one account created


def test_returns_none_when_no_register_endpoint():
    class _Dead:
        def http_request(self, method, url, **kw):
            return {"status": 404, "body": "nf"}
    assert register_json_spa([], _Dead(), "https://t/", log=lambda m: None) is None


class _CrapiLikeApp:
    """Microservice app (crAPI-style): auth is behind /identity, signup needs a UNIQUE number,
    and login lives at /identity/api/auth/login — the register path is never a root path."""

    def __init__(self):
        self.numbers = set()

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        import json as _j
        import urllib.parse as _up
        path = _up.urlsplit(url).path
        if method == "GET":
            # identity is the auth gateway; these noise segments also resolve (like real crAPI)
            if path in ("/identity", "/static", "/images", "/health", "/chatbot"):
                return {"status": 301, "body": ""}
            return {"status": 404, "body": "nf"}
        if path == "/identity/api/auth/signup" and method == "POST":
            d = _j.loads(body) if body else {}
            if not (d.get("email") and d.get("password") and d.get("number")):
                return {"status": 400, "body": "bad"}
            if d["number"] in self.numbers:
                return {"status": 403, "body": '{"message":"Number already registered"}'}
            self.numbers.add(d["number"])
            return {"status": 200, "body": '{"message":"ok"}'}       # no session on signup
        if path == "/identity/api/auth/login" and method == "POST":
            d = _j.loads(body) if body else {}
            if d.get("email") and d.get("password"):
                return {"status": 200, "body": '{"token":"ey.sessiontoken.abcdefghij"}'}
            return {"status": 401, "body": "no"}
        return {"status": 404, "body": "nf"}


def test_live_prefixes_keeps_only_resolving_segments():
    from owlforge.engine.spaseed import _live_prefixes
    live = _live_prefixes([], _CrapiLikeApp(), "https://t")
    assert "identity" in live


def test_registers_on_microservice_prefixed_api(tmp_path, monkeypatch):
    from owlforge.engine.spaseed import register_json_spa
    noisy_inv = [{"url": f"https://t/{seg}/x", "method": "GET", "params": [], "source": "katana"}
                 for seg in ("static", "images", "health", "chatbot")]
    ident = register_json_spa(noisy_inv, _CrapiLikeApp(), "https://t/", log=lambda m: None)
    assert ident is not None
    assert ident["login"]["url"].endswith("/identity/api/auth/signup")
    assert "Bearer" in ident["headers"].get("Authorization", "")     # logged in via derived path
