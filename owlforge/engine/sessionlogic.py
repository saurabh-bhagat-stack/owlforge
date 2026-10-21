"""Session-lifecycle checks — logout invalidation.

Deterministic, self-contained: if an authenticated session still grants access to a
session-gated page AFTER the logout endpoint has been hit, the server is not invalidating
the session server-side (a real session-management flaw). Guarded against false positives:
the page must be genuinely session-gated (anonymous is denied) and the logout endpoint must
respond; because a GET to /logout might not be the app's real logout mechanism, this is
filed as a CANDIDATE for manual verification rather than auto-validated.

Session *fixation* needs to observe the login transition's cookies (pre vs post auth) and
is not done here — it requires hooks into the auth flow (tracked as a TODO).
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable

_LOGOUT = ("/logout", "/log-out", "/signout", "/sign-out", "/logoff", "/account/logout",
           "/session/destroy", "/sessions/destroy", "/users/sign_out", "/auth/logout")


def _get(sandbox, method, url, headers):
    try:
        return sandbox.http_request(method or "GET", url, headers=headers or {},
                                    params=None, body=None) or {}
    except Exception:
        return {}


def _usable(r):
    return int(r.get("status") or 0) == 200 and len(r.get("body") or "") >= 50


def _authed_gated_page(inventory, sandbox, session_headers, similar, is_login):
    """An endpoint that is 200 with the session AND denied to anonymous (session-gated)."""
    from owlforge.engine.accesscontrol import _is_object_endpoint
    cand = [it for it in inventory if it.get("url") and _is_object_endpoint(it)]
    for it in cand[:25]:
        url, method = it["url"], (it.get("method") or "GET").upper()
        a = _get(sandbox, method, url, session_headers)
        if not _usable(a):
            continue
        anon = _get(sandbox, method, url, {})
        if _usable(anon) and similar(a["body"], anon.get("body", "")) \
                and not is_login(anon.get("body", "")):
            continue  # public page -> not session-gated
        return url, method, a["body"]
    return None


def _find_logout(inventory, sandbox, session_headers):
    urls = [it["url"] for it in inventory
            if any(seg in (it.get("url") or "").lower() for seg in _LOGOUT)]
    for u in urls[:5]:
        r = _get(sandbox, "GET", u, session_headers)
        if int(r.get("status") or 0) in (200, 301, 302, 303, 307, 308):
            return u
    # probe a few common logout paths under the target origin
    if inventory:
        from urllib.parse import urlsplit, urlunsplit
        base = urlsplit(inventory[0]["url"])
        for p in ("/logout", "/account/logout", "/signout"):
            u = urlunsplit((base.scheme, base.netloc, p, "", ""))
            r = _get(sandbox, "GET", u, session_headers)
            if int(r.get("status") or 0) in (200, 301, 302, 303, 307, 308):
                return u
    return None


def _file(assessment_id, url, method, note):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Session not invalidated after logout",
            severity="medium", status="candidate", confidence="low",
            endpoint=url, method=method,
            technical_analysis=note,
            proof_of_concept=f"session still accesses {url} after hitting the logout endpoint",
            impact="A stolen or leaked session token may remain valid after the user logs "
                   "out, extending the window for session hijacking.",
            remediation="Invalidate the session server-side on logout (destroy it, don't just "
                        "clear the client cookie); rotate the session id on login.",
            validation_note="possible session-invalidation flaw — verify the logout "
                            "mechanism manually (needs manual verification)"))
        s.commit()


def session_scan(assessment_id, inventory, sandbox, session_headers,
                 log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None or not session_headers:
        return 0
    from owlforge.engine.validate import _looks_like_login, _similar

    page = _authed_gated_page(inventory, sandbox, session_headers, _similar, _looks_like_login)
    if not page:
        return 0
    logout = _find_logout(inventory, sandbox, session_headers)
    if not logout:
        return 0
    url, method, before = page
    _get(sandbox, "GET", logout, session_headers)          # perform the logout
    after = _get(sandbox, method, url, session_headers)     # reuse the same session
    if _usable(after) and _similar(before, after.get("body", "")) \
            and not _looks_like_login(after.get("body", "")):
        _file(assessment_id, url, method,
              f"After requesting {logout}, the same session still returns the protected page "
              f"{method} {url} (200, equivalent content) — the session was not invalidated "
              "server-side.")
        log("session-logic: session still valid after logout (candidate)")
        return 1
    log("session-logic: session invalidated on logout (or logout not confirmable)")
    return 0
