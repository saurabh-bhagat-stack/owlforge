"""Browser-driven login — log in the way a user does, in real Chromium, and keep the session.

The SPA recon already runs in a real browser, but login historically bypassed it with a raw
HTTP form POST — which does not authenticate JS-driven / SPA logins (XHR to an API, CSRF
nonces, client-side hashing, a token stashed in localStorage). This drives the sandbox
browser to fill the username/password fields and submit, then captures the resulting
storage_state (cookies AND localStorage token) as the session — the same capture the SSO
flow uses, but automated.

It also extracts credentials a page DISPLAYS in any format (demo/test creds, with or without
'username:'/'password:' labels) using the model — label-free, where regex cannot help — and
leaves the deterministic try-and-verify to owlforge.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import urljoin

from owlforge.engine.authbroker import storage_state_to_headers


def browser_login_session(sandbox, login_url, username, password, target, *,
                          user_field: str | None = None, pass_field: str | None = None,
                          check_url: str | None = None, success: str | None = None,
                          headers: dict | None = None,
                          log: Callable[[str], None] = lambda m: None) -> tuple[dict, bool]:
    """Log in through the real browser and return (session_headers, confirmed).
    ({}, False) when the browser login is unavailable (older sandbox image) or no session
    resulted — callers then fall back to the raw-HTTP path."""
    if sandbox is None or not hasattr(sandbox, "browser_login"):
        return {}, False
    try:
        res = sandbox.browser_login(login_url, username, password, user_field=user_field,
                                    pass_field=pass_field, headers=headers,
                                    check_url=check_url or urljoin(target, "/"),
                                    success=success) or {}
    except Exception as e:
        log(f"browser login unavailable ({type(e).__name__}) — falling back to HTTP login")
        return {}, False
    if res.get("error"):
        log(f"browser login error: {res['error']}")
        return {}, False
    state = res.get("storage_state") or {}
    if isinstance(state, dict) and state.get("error"):
        return {}, False
    hdrs = storage_state_to_headers(state, target)
    confirmed = bool(res.get("success")) or bool(res.get("logged_in_hint"))
    if res.get("success") is False and not res.get("logged_in_hint"):
        return {}, False                     # explicit success-string check failed
    if not hdrs:
        return {}, False
    return hdrs, confirmed


# ---- model-assisted, label-free extraction of credentials a page displays ---------------
_CRED_SYS = (
    "You extract login credentials that a web page DISPLAYS to the visitor (demo/test/guest "
    "accounts shown in the UI, hints, tables, comments or prose), in ANY format, with or "
    "without 'username'/'password' labels. Output ONLY a compact JSON array of objects "
    '{"username": "...", "password": "..."} for credentials actually shown as a usable pair. '
    "If none are shown, output []. Do not invent or guess values."
)
_JSON_ARRAY = re.compile(r"\[.*\]", re.S)


def extract_displayed_credentials(client, page_text: str,
                                  log: Callable[[str], None] = lambda m: None) -> list[dict]:
    """Ask the model for any credentials the page shows (label-free). Returns a list of
    {username, password}. Empty when no client, no text, or nothing shown."""
    if client is None or not (page_text or "").strip():
        return []
    from owlforge.llm.base import Message
    snippet = page_text[:6000]
    try:
        turn = client.chat(
            [Message(role="system", content=_CRED_SYS),
             Message(role="user", content=f"Page content:\n\n{snippet}")],
            temperature=0, max_tokens=400)
        raw = turn.content or ""
    except Exception as e:
        log(f"cred extraction failed: {type(e).__name__}: {e}")
        return []
    m = _JSON_ARRAY.search(raw)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except Exception:
        return []
    out = []
    for row in data if isinstance(data, list) else []:
        if isinstance(row, dict):
            u, p = str(row.get("username", "")).strip(), str(row.get("password", "")).strip()
            if u and p and len(u) <= 128 and len(p) <= 128:
                out.append({"username": u, "password": p})
    return out[:5]
