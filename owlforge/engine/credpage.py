"""Harvest credentials displayed on login / auth pages, then log in.

Deliberately-vulnerable apps (and plenty of real staging apps) print test credentials
right on the login page — sometimes across a two-step flow (username page -> password
page). owlforge now reads the auth flow, extracts the shown username/password, and
establishes a session so the rest of the assessment runs AUTHENTICATED. The user was
right: the app has to actually look at the page, not assume.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urljoin

from owlforge.engine.csrf import _is_token_name, extract_token

RequestFn = Callable[..., dict]

# credential hints shown as "<b>Username</b> carlos", "username: carlos", var username='carlos'
_USER_RE = re.compile(
    r"(?:<b>\s*user(?:name)?\s*</b>\s*|user(?:name)?[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9._@-]{2,40})", re.I)
_PASS_RE = re.compile(
    r"(?:<b>\s*pass(?:word)?\s*</b>\s*|pass(?:word)?[\"']?\s*[:=]\s*[\"']?)([^\s\"'<]{2,60})", re.I)
_LOGIN_PATHS = ("/login", "/my-account", "/signin", "/sign-in", "/account/login",
                "/users/login", "/user/login", "/auth/login")
_BAD_VALUES = {"username", "password", "text", "the", "your", "email", "none", "true", "false"}


def _extract_creds(html: str) -> dict:
    out: dict[str, str] = {}
    um = _USER_RE.search(html or "")
    if um and um.group(1).lower() not in _BAD_VALUES:
        out["username"] = um.group(1)
    pm = _PASS_RE.search(html or "")
    if pm and pm.group(1).lower() not in _BAD_VALUES:
        out["password"] = pm.group(1)
    return out


def _extract_form(html: str) -> dict:
    out: dict = {"action": None, "user_field": None, "pass_field": None, "csrf_field": None}
    fm = re.search(r"""<form[^>]*\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", html or "", re.I)
    if fm:
        out["action"] = fm.group(1) or fm.group(2) or fm.group(3)
    attr_re = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))')
    for im in re.finditer(r"<input[^>]*>", html or "", re.I):
        attrs = {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
                 for m in attr_re.finditer(im.group(0))}
        name, typ = attrs.get("name", ""), attrs.get("type", "").lower()
        if not name:
            continue
        if typ == "password" or "pass" in name.lower():
            out["pass_field"] = name
        elif _is_token_name(name):
            out["csrf_field"] = name
        elif ("user" in name.lower() or "email" in name.lower()) and not out["user_field"]:
            out["user_field"] = name
    return out


def _parse_cookie(resp: dict) -> str:
    from owlforge.engine.auth import _parse_set_cookie
    hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    return _parse_set_cookie(hdrs.get("set-cookie", ""))


def establish_from_login_page(target: str, sandbox, request_fn: RequestFn,
                              log: Callable[[str], None] = lambda m: None) -> tuple[dict, str]:
    """Find a login page, harvest shown credentials (following a multi-step username->
    password flow), log in, and return (session_headers, provenance). Cookie-aware: a
    session jar is kept so session-bound CSRF tokens validate. ({}, "") if none."""
    from owlforge.engine.auth import _parse_set_cookie

    base = target.rstrip("/")
    for path in _LOGIN_PATHS:
        jar: dict[str, str] = {}

        def rq(method, url, body=None, _jar=jar):
            headers: dict[str, str] = {}
            if body is not None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if _jar:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in _jar.items())
            try:
                r = request_fn(method, url, headers=headers or None, body=body) or {}
            except Exception:
                return {}
            for k, v in (r.get("headers") or {}).items():
                if k.lower() == "set-cookie":
                    for pair in _parse_set_cookie(v).split("; "):
                        if "=" in pair:
                            ck, cv = pair.split("=", 1)
                            _jar[ck.strip()] = cv.strip()
            return r

        lu = base + path
        page = rq("GET", lu)
        html = page.get("body") or ""
        if int(page.get("status") or 0) >= 400 or ("<form" not in html.lower()
                                                   and "password" not in html.lower()):
            continue
        creds = _extract_creds(html)
        form = _extract_form(html)
        action = urljoin(lu, form["action"] or path)

        # reveal the password across up to 2 steps (username page -> password page)
        for _ in range(2):
            if creds.get("password") or not creds.get("username"):
                break
            tok = extract_token(html)
            step = {form.get("user_field") or "username": creds["username"]}
            if tok:
                step[tok[0]] = tok[1]
            r2 = rq("POST", action, _urlencode(step))
            html = r2.get("body") or ""
            for k, v in _extract_creds(html).items():
                creds.setdefault(k, v)
            f2 = _extract_form(html)
            if f2["action"]:
                action = urljoin(lu, f2["action"])
            if f2["pass_field"]:
                form["pass_field"] = f2["pass_field"]
            if f2["user_field"]:
                form["user_field"] = f2["user_field"]

        if not (creds.get("username") and creds.get("password")):
            continue

        tok = extract_token(html)
        params = {(form.get("user_field") or "username"): creds["username"],
                  (form.get("pass_field") or "password"): creds["password"]}
        if tok:
            params[tok[0]] = tok[1]
        rq("POST", action, _urlencode(params))
        if not jar:
            continue
        cookie_hdr = "; ".join(f"{k}={v}" for k, v in jar.items())
        # verify we are actually logged in
        check = rq("GET", urljoin(lu, "/my-account"))
        body = (check.get("body") or "").lower()
        if "log out" in body or "logout" in body or creds["username"].lower() in body:
            log(f"harvested login-page credentials ({creds['username']}:***) and logged in via {path}")
            return {"Cookie": cookie_hdr}, f"{creds['username']} from {path}"
    return {}, ""


def _urlencode(d: dict) -> str:
    from urllib.parse import urlencode
    return urlencode(d)
