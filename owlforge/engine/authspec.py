"""Low-friction credential & session specs from the CLI — so the common case needs no
YAML file. Both flags are repeatable (one identity each) and also accept a comma list.

  --cred  user:pass            (or "user pass"); @label / :role optional; repeat for A/B/admin
  --session "<spec>"           a Cookie string, a 'Header: value', several joined with ' | ',
                               or a pasted copy-as-cURL; @label optional; repeat per identity

Everything resolves to plain identity dicts the existing identity machinery understands, so
access-control / IDOR / re-auth all keep working unchanged.
"""

from __future__ import annotations

import re
import shlex

_PRIV = ("admin", "administrator", "superuser", "root", "super", "role_admin")
_ROLE_WORDS = {"admin", "administrator", "superuser", "root", "manager", "staff",
               "moderator", "user", "guest", "anonymous", "readonly"}


def _role_for(label: str, explicit: str | None = None) -> str:
    if explicit:
        return "admin" if explicit.lower() in _PRIV else explicit.lower()
    return "admin" if any(k in (label or "").lower() for k in _PRIV) else "user"


def _strip_label(part: str) -> tuple[str | None, str]:
    """A leading '@label ' sets the identity label (unambiguous: cookies/headers never
    start with '@'). Returns (label, rest)."""
    part = part.strip()
    if part.startswith("@"):
        m = re.match(r"@(\S+)\s+(.*)$", part, re.S)
        if m:
            return m.group(1), m.group(2).strip()
    return None, part


def _split_items(raw: str) -> list[str]:
    """Split one flag value into identities on commas (convenience); a single item with no
    top-level comma is returned as-is so cURL/headers with commas still work when passed alone."""
    raw = (raw or "").strip()
    return [p.strip() for p in raw.split(",") if p.strip()] if "," in raw else ([raw] if raw else [])


def _split_user_pass(rest: str) -> tuple[str, str, str | None]:
    """'user:pass', 'user:pass:role', or 'user pass' -> (user, pass, role|None). Splits the
    username on the FIRST colon (so passwords may contain ':'); a trailing ':<role-word>' is
    taken as the role only when it is a known role keyword."""
    rest = rest.strip()
    role = None
    if ":" in rest:
        head, _, tail = rest.rpartition(":")
        if head and tail.lower() in _ROLE_WORDS:
            rest, role = head, tail.lower()
        user, _, pw = rest.partition(":")
    else:
        user, _, pw = rest.partition(" ")
    return user.strip(), pw.strip(), role


def parse_creds(values: list[str] | None) -> list[dict]:
    """--cred values -> [{label, role, user, password}]. Order gives default labels
    user_a, user_b, … so two users are ready for horizontal IDOR out of the box."""
    out: list[dict] = []
    for raw in values or []:
        for item in _split_items(raw):
            label, rest = _strip_label(item)
            user, pw, role = _split_user_pass(rest)
            if not user or not pw:
                continue
            label = label or user
            out.append({"label": label, "role": _role_for(label, role),
                        "user": user, "password": pw})
    # stable default labels when the operator gave none distinct (user_a, user_b, …)
    for i, c in enumerate(out):
        c.setdefault("order", i)
    return out


def _canon(name: str) -> str:
    n = name.strip().lower()
    return {"cookie": "Cookie", "authorization": "Authorization"}.get(n, name.strip())


def parse_curl(cmd: str) -> dict:
    """Pull Cookie + -H headers out of a pasted `copy as cURL` command."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    headers: dict[str, str] = {}
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("-H", "--header") and i + 1 < len(toks):
            hv = toks[i + 1]
            if ":" in hv:
                n, v = hv.split(":", 1)
                headers[_canon(n)] = v.strip()
            i += 2
            continue
        if t in ("-b", "--cookie") and i + 1 < len(toks):
            headers["Cookie"] = toks[i + 1].strip()
            i += 2
            continue
        i += 1
    return headers


def _spec_to_headers(spec: str) -> dict:
    """A session spec -> headers. Accepts a cURL paste, 'Name: value' header(s) joined with
    '|', or a bare 'k=v; k2=v2' cookie string."""
    spec = spec.strip()
    if spec[:5].lower() == "curl " or spec.lower().startswith("curl\t"):
        return parse_curl(spec)
    headers: dict[str, str] = {}
    for seg in spec.split("|"):
        seg = seg.strip()
        if not seg:
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+)$", seg, re.S)
        if m and "=" not in m.group(1):          # a real 'Header: value'
            headers[_canon(m.group(1))] = m.group(2).strip()
        else:                                     # a bare cookie string
            headers["Cookie"] = (headers.get("Cookie", "") + "; " + seg).strip("; ")
    return headers


def parse_sessions(values: list[str] | None) -> list[dict]:
    """--session values -> [{label, role, headers}]; one identity per flag (repeat for more)."""
    out: list[dict] = []
    for raw in values or []:
        label, rest = _strip_label(raw.strip())
        headers = _spec_to_headers(rest)
        if headers:
            out.append({"label": label or "", "role": _role_for(label or ""),
                        "headers": headers})
    return out


def _http_login(form: dict, cred: dict, request_fn, log) -> dict:
    """Best-effort raw-HTTP form login (fallback when the sandbox browser login is absent)."""
    from urllib.parse import urljoin

    from owlforge.engine.auth import AuthContext, establish_session
    from owlforge.engine.csrf import extract_token
    url = form["url"]
    page = request_fn("GET", url) or {}
    params = {(form.get("user_field") or "username"): cred["user"],
              (form.get("pass_field") or "password"): cred["password"]}
    tok = extract_token(page.get("body") or "")
    if tok:
        params[tok[0]] = tok[1]
    action = urljoin(url, form.get("action") or url)
    ctx = AuthContext(mode="login", login_url=action, login_params=params)
    return establish_session(ctx, request_fn, log=log) or {}


def _spa_login_probe(sandbox, target: str, cred: dict,
                     log=lambda m: None) -> tuple[str | None, dict | None]:
    """SPA logins are rendered client-side, so the HTTP form-finder misses them. Drive the
    real browser against the likely login routes (agentd auto-detects the fields in the LIVE
    DOM, which a truncated page dump can hide) and return (login_url, session_headers) for the
    first route that yields a CONFIRMED session. (None, None) when none authenticate. Only
    genuine login paths are tried, never the app root, so no stray input is filled."""
    if sandbox is None or not hasattr(sandbox, "browser_login"):
        return None, None
    from owlforge.engine.browserlogin import browser_login_session
    from owlforge.engine.credpage import _LOGIN_PATHS
    base = target.rstrip("/")
    paths: list[str] = []
    for pth in _LOGIN_PATHS:                  # hash-routed variant first — most SPAs use it
        for cand in ("/#" + pth, pth):
            if cand not in paths:
                paths.append(cand)
    for path in paths:
        url = base + path
        hdrs, confirmed = browser_login_session(
            sandbox, url, cred["user"], cred["password"], target, log=lambda m: None)
        if hdrs and confirmed:
            log(f"[cred] SPA login confirmed at {url}")
            return url, hdrs
    return None, None


def resolve_cred_identities(creds: list[dict], target: str, sandbox, request_fn,
                            log=lambda m: None) -> list[dict]:
    """Log in each --cred pair by auto-finding the login form (no URL needed). Returns identity
    dicts {label, role, headers, login}; `login` is a reusable spec for mid-scan re-auth."""
    if not creds:
        return []
    from owlforge.engine.browserlogin import browser_login_session
    from owlforge.engine.credpage import find_login_form
    form = find_login_form(target, request_fn, log=log)
    primed: dict | None = None            # session already captured for creds[0] by the probe
    if not form:
        spa_url, primed = _spa_login_probe(sandbox, target, creds[0], log)
        if spa_url:
            form = {"url": spa_url, "action": None, "user_field": None, "pass_field": None}
    if not form:
        log("[cred] no login form found on the target — cannot use --cred")
        return []
    out = []
    for i, c in enumerate(creds):
        if i == 0 and primed:
            hdrs = primed                 # reuse the probe's confirmed session (no re-login)
        else:
            hdrs, _ok = browser_login_session(
                sandbox, form["url"], c["user"], c["password"], target,
                user_field=form.get("user_field"), pass_field=form.get("pass_field"), log=log)
            if not hdrs:
                hdrs = _http_login(form, c, request_fn, log)
        if hdrs:
            log(f"[cred] {c['label']}: logged in as {c['user']}")
            out.append({"label": c["label"], "role": c["role"], "headers": hdrs,
                        "login": {"url": form["url"], "action": form.get("action"),
                                  "user": c["user"], "password": c["password"],
                                  "user_field": form.get("user_field") or "username",
                                  "pass_field": form.get("pass_field") or "password"}})
        else:
            log(f"[cred] {c['label']}: login FAILED for {c['user']}")
    return out
