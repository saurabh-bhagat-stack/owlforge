"""Authentication context for assessments.

Recon/testing must run UNAUTHENTICATED and AUTHENTICATED — the logged-in surface is
usually larger and higher-value. Auth resolves ONCE into a set of session headers
that every sandbox HTTP request then carries.

Modes:
  unauth  — no credentials (default).
  session — operator supplies a ready session: a Cookie and/or Authorization/custom
            header (they logged in themselves). Most robust.
  login   — operator supplies a login URL + form fields (incl. credentials) + an
            optional success signal; owlforge form-logs-in and captures Set-Cookie.

Credentials are operator-supplied for an authorized target and injected into sandbox
tools; they are never echoed back in events or reports.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlencode

# request_fn(method, url, headers=?, params=?, body=?) -> dict(status, headers, body)
RequestFn = Callable[..., dict]


@dataclass
class AuthContext:
    mode: str = "unauth"
    headers: dict[str, str] = field(default_factory=dict)
    login_url: str | None = None
    login_params: dict[str, str] = field(default_factory=dict)
    login_success: str | None = None


def _parse_set_cookie(raw: str) -> str:
    """Best-effort: turn a Set-Cookie header value into a 'k=v; k2=v2' Cookie string.
    (For flaky login flows, prefer `session` mode and paste the Cookie directly.)"""
    if not raw:
        return ""
    pairs = []
    # split on commas that separate cookies (a comma followed by `token=`), not attrs
    for part in re.split(r",(?=\s*[^=;,\s]+=)", raw):
        kv = part.strip().split(";", 1)[0].strip()
        if "=" in kv and not kv.lower().startswith(("expires=", "path=", "domain=", "max-age=", "samesite=")):
            pairs.append(kv)
    return "; ".join(pairs)


def establish_session(
    auth: AuthContext,
    request_fn: RequestFn,
    log: Callable[[str], None] = lambda m: None,
) -> dict[str, str]:
    """Return the headers to attach to every authenticated request (empty for unauth)."""
    if auth.mode == "unauth":
        return {}
    if auth.mode == "session":
        return dict(auth.headers)
    if auth.mode == "login":
        if not auth.login_url:
            log("login mode but no login_url set")
            return dict(auth.headers)
        body = urlencode(auth.login_params)
        hdrs = {**auth.headers, "Content-Type": "application/x-www-form-urlencoded"}
        r = request_fn("POST", auth.login_url, headers=hdrs, body=body) or {}
        resp_headers = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
        set_cookie = resp_headers.get("set-cookie", "")
        cookie = _parse_set_cookie(set_cookie)
        ok = True
        if auth.login_success:
            blob = f"{r.get('status', '')} {set_cookie} {r.get('body', '') or ''}"
            ok = auth.login_success.lower() in blob.lower()
        session = dict(auth.headers)
        if cookie:
            existing = session.get("Cookie", "")
            session["Cookie"] = f"{existing}; {cookie}" if existing else cookie
        log(f"login: status={r.get('status')} cookie={'captured' if cookie else 'none'} success={ok}")
        return session
    return {}
