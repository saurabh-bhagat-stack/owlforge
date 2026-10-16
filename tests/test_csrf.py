"""CSRF token handling + CSRF vuln-class planning."""

from __future__ import annotations

from owlforge.engine.csrf import extract_token, fresh_token, with_fresh_token


def test_extract_token_from_hidden_input_and_meta():
    assert extract_token('<input type="hidden" name="csrf_token" value="TOK1">') == ("csrf_token", "TOK1")
    assert extract_token('<input name="__RequestVerificationToken" value="NET2">') == (
        "__RequestVerificationToken", "NET2")
    assert extract_token('<meta name="csrf-token" content="M3">') == ("csrf-token", "M3")
    assert extract_token('<input name="username" value="x">') is None


def test_fresh_and_with_fresh_token_handle_rotation():
    calls = {"n": 0}

    def reqfn(method, url, headers=None, params=None, body=None):
        calls["n"] += 1
        return {"status": 200, "body": f'<input name="_csrf" value="rot{calls["n"]}">'}

    assert fresh_token(reqfn, "https://t/form") == ("_csrf", "rot1")
    merged = with_fresh_token(reqfn, "https://t/form", {"email": "a@b.c"})
    assert merged == {"email": "a@b.c", "_csrf": "rot2"}   # re-fetched a fresh (rotated) token


def test_plan_tasks_adds_csrf_for_state_changing_endpoints():
    from owlforge.engine.classify import CSRF
    from owlforge.engine.orchestrator import plan_tasks

    inv = [
        {"url": "https://t/login", "method": "POST", "params": ["username", "csrf"]},
        {"url": "https://t/account/email", "method": "POST", "params": []},
        {"url": "https://t/catalog", "method": "GET", "params": ["category"]},
    ]
    tasks = plan_tasks(inv)
    csrf_urls = {t["url"] for t in tasks.get(CSRF, [])}
    assert csrf_urls == {"https://t/login", "https://t/account/email"}   # POSTs only, not the GET
