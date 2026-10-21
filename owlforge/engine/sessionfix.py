"""Session fixation detection.

A login should issue a NEW session identifier. If, after a confirmed-successful login, the
pre-authentication session cookie is still valid and unchanged (and no other session cookie
was rotated in), an attacker who fixes a victim's session id can hijack the authenticated
session. Sound guards: the login must look successful (operator success-marker, or a
redirect away from the login page) AND no session-like cookie may have changed; otherwise
nothing is filed.

Needs a known login flow (a form-login identity). The raw, un-collapsed Set-Cookie list
comes from agentd (httpx dict() would merge them).
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable

_SESSION_NAMES = ("session", "sess", "sid", "auth", "jsessionid", "phpsessid",
                  "connect.sid", "asp.net", "csrftoken", "_session", "sessionid")


def _name(sc: str) -> str:
    return sc.split("=", 1)[0].strip()


def _is_session(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in _SESSION_NAMES)


def _val(set_cookies, name):
    for sc in set_cookies:
        if _name(sc) == name:
            return sc.split("=", 1)[1].split(";", 1)[0].strip()
    return None


def _session_cookie(set_cookies):
    for sc in set_cookies:
        if _is_session(_name(sc)):
            n = _name(sc)
            return n, _val(set_cookies, n)
    return None, None


def _login_ok(post, success, login_url):
    status = int(post.get("status") or 0)
    body = (post.get("body") or "")
    loc = (post.get("headers") or {}).get("location", "") or (post.get("headers") or {}).get("Location", "")
    if success and success.lower() in body.lower():
        return True
    if 300 <= status < 400 and login_url.split("?")[0] not in (loc or ""):
        return True
    return False


def _file(assessment_id, url, name):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Session fixation (session id not rotated on login)",
            severity="medium", status="validated", confidence="high",
            endpoint=url, method="POST",
            technical_analysis=(f"After a successful login at {url}, the pre-authentication "
                                f"session cookie '{name}' remained valid and unchanged — the "
                                "server did not issue a new session identifier. An attacker who "
                                "fixes a victim's session id can take over the authenticated session."),
            proof_of_concept=f"pre-auth {name}=X survives login unchanged -> fixed session id",
            impact="Session hijacking: an attacker who plants a known session id gains the "
                   "victim's authenticated session after they log in.",
            remediation="Issue a fresh session id on every authentication (and invalidate the "
                        "old one); set HttpOnly/Secure/SameSite.",
            validation_note="session cookie not rotated after a confirmed login (deterministic)"))
        s.commit()


def session_fixation_scan(assessment_id, sandbox, logins,
                          log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None or not logins:
        return 0
    filed = 0
    for login in logins:
        url = login.get("url")
        if not url:
            continue
        data = login.get("data", "") or ""
        success = login.get("success", "") or ""
        try:
            pre = sandbox.http_request("GET", url, follow_redirects=False) or {}
        except Exception:
            continue
        name, pre_val = _session_cookie(pre.get("set_cookie") or [])
        if not name or not pre_val:
            continue
        hdrs = {"Cookie": f"{name}={pre_val}", "Content-Type": "application/x-www-form-urlencoded"}
        try:
            post = sandbox.http_request("POST", url, body=data, headers=hdrs,
                                        follow_redirects=False) or {}
        except Exception:
            continue
        if not _login_ok(post, success, url):
            continue
        post_sc = post.get("set_cookie") or []
        # rotated if ANY session-like cookie changed/added (incl. same name, new value)
        rotated = False
        for sc in post_sc:
            n = _name(sc)
            if _is_session(n):
                v = _val(post_sc, n)
                if n != name or (v is not None and v != pre_val):
                    rotated = True
                    break
        if not rotated:
            _file(assessment_id, url, name)
            filed += 1
    if filed:
        log(f"session-fixation: {filed} login(s) reuse the pre-auth session id")
    return filed
