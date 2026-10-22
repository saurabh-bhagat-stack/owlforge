"""Carry a token/localStorage SPA session into the hunt (bearer + cookie)."""
from __future__ import annotations

from owlforge.engine.authbroker import (
    _bearer_from_localstorage,
    storage_state_to_cookie,
    storage_state_to_headers,
)

JWT = "eyJhbGci.eyJzdWIiOiIx.c2lnbmF0dXJl"


def _state(ls_name, ls_value):
    return {"cookies": [{"name": "sid", "value": "abc", "domain": "app.test"}],
            "origins": [{"origin": "https://app.test",
                         "localStorage": [{"name": ls_name, "value": ls_value}]}]}


def test_bearer_from_jwt_shaped_value():
    assert _bearer_from_localstorage(_state("anything", JWT)) == JWT


def test_bearer_from_token_named_key_json_value():
    st = _state("auth", '{"access_token":"' + JWT + '","expires":3600}')
    assert _bearer_from_localstorage(st) == JWT


def test_bearer_opaque_token_named_key():
    st = _state("access_token", "opaque-0123456789abcdef")
    assert _bearer_from_localstorage(st) == "opaque-0123456789abcdef"


def test_no_token_returns_none():
    st = _state("theme", "dark")
    assert _bearer_from_localstorage(st) is None


def test_headers_combine_cookie_and_bearer():
    h = storage_state_to_headers(_state("access_token", JWT), "https://app.test")
    assert h["Cookie"] == "sid=abc"
    assert h["Authorization"] == f"Bearer {JWT}"


def test_cookie_only_when_no_token():
    st = _state("theme", "dark")
    assert storage_state_to_headers(st, "https://app.test") == storage_state_to_cookie(st, "https://app.test")
    assert "Authorization" not in storage_state_to_headers(st, "https://app.test")
