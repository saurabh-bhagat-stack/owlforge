"""Auth Broker — interactive SSO/MFA session capture.

The login runs in the SANDBOX's own headed Chromium, exposed to the operator over
noVNC (nothing installed on their machine). The operator completes SSO / MFA / CAPTCHA
in that browser; owlforge then captures the authenticated storage_state, persists it to
a project file for reuse, and converts its cookies to a session header for the hunt.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from urllib.parse import urlparse


def storage_state_to_cookie(state: dict, target: str) -> dict:
    """Turn a Playwright storage_state into a Cookie header for the target's host.
    (localStorage/token-based sessions need browser-driven requests — not covered here.)"""
    host = urlparse(target if "://" in target else "https://" + target).netloc.split(":")[0]
    pairs = []
    for c in (state or {}).get("cookies", []) or []:
        dom = str(c.get("domain", "")).lstrip(".").lower()
        if not dom or dom == host or host.endswith("." + dom) or dom.endswith("." + host):
            pairs.append(f"{c['name']}={c['value']}")
    return {"Cookie": "; ".join(pairs)} if pairs else {}


_JWT = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_TOKEN_KEYS = ("access_token", "id_token", "auth_token", "accesstoken", "authorization",
               "bearer", "jwt", "token", "auth", "session")


def _bearer_from_localstorage(state: dict) -> str | None:
    """Best-effort bearer token from a storage_state's localStorage: a JWT-shaped value,
    or a token-named key (whose value may be a raw token or JSON wrapping one)."""
    fallback = None
    for origin in (state or {}).get("origins", []) or []:
        for item in origin.get("localStorage", []) or []:
            name = str(item.get("name", "")).lower()
            raw = str(item.get("value", "")).strip()
            if not raw:
                continue
            val = raw.strip().strip('"')
            if _JWT.fullmatch(val):
                return val
            if any(k in name for k in _TOKEN_KEYS):
                m = _JWT.search(raw)       # value may be JSON like {"access_token":"x.y.z"}
                if m:
                    return m.group(0)
                if val and " " not in val and len(val) >= 16:
                    fallback = fallback or val
    return fallback


def storage_state_to_headers(state: dict, target: str) -> dict:
    """Cookie header PLUS an Authorization: Bearer header when the SPA keeps its session
    as a token in localStorage (modern JWT SPAs), so the hunt carries the real session."""
    headers = dict(storage_state_to_cookie(state, target))
    tok = _bearer_from_localstorage(state)
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers


def capture_sso_session(
    sandbox_client,
    novnc_url: str,
    login_url: str,
    *,
    headers: dict | None = None,
    persist_path: str | None = None,
    prompt_fn: Callable[[str], str] = input,
    log: Callable[[str], None] = print,
) -> dict:
    """Drive the interactive SSO capture. Returns the captured storage_state ({} on
    failure or when no interactive terminal is available)."""
    if not sys.stdin.isatty():
        log("SSO capture needs an interactive terminal (stdin is not a TTY) — skipping.")
        return {}
    try:
        started = sandbox_client.sso_start(login_url, headers=headers)
    except Exception as e:
        log(f"SSO start failed: {type(e).__name__}: {e}")
        return {}
    if started.get("error"):
        log(f"SSO start error: {started['error']}")
        return {}
    sid = started["session_id"]
    log("")
    log("  Open this URL in your browser, complete the login, then return here:")
    log(f"    {novnc_url}")
    try:
        prompt_fn("  Press Enter once you are logged in… ")
    except (EOFError, KeyboardInterrupt):
        log("SSO capture cancelled.")
    try:
        finished = sandbox_client.sso_finish(sid)
    except Exception as e:
        log(f"SSO finish failed: {type(e).__name__}: {e}")
        return {}
    state = finished.get("storage_state") or {}
    if isinstance(state, dict) and state.get("error"):
        log(f"SSO capture error: {state['error']}")
        return {}
    if persist_path and state:
        try:
            with open(persist_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            log(f"  session saved to {persist_path}")
        except Exception as e:
            log(f"  could not persist session: {e}")
    n = len((state or {}).get("cookies", []) or [])
    log(f"  captured {n} cookie(s) from the authenticated session")
    return state
