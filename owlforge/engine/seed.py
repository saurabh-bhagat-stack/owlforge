"""Stateful seeding — owlforge behaves like a tester: if the app lets you register, it
makes a throwaway account; if it lets you create/upload things, it creates one, captures the
identifier the app hands back, and feeds that to access-control testing so IDOR/BOLA can be
checked on data owlforge created itself.

Part of the deep authenticated pipeline (no flag). Writes are benign and marker-labelled
(`owlforge test <rand>`); it only ADDS test entries — it never edits or deletes anyone
else's data. On an authorized engagement this is normal tester behaviour.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import urlencode, urljoin

_INPUT = re.compile(r"<input\b[^>]*>", re.I)
_TEXTAREA = re.compile(r"<textarea\b([^>]*)>", re.I)
_ATTR = re.compile(r'(\w[\w:-]*)\s*=\s*"([^"]*)"')

_REG_HINT = ("register", "signup", "sign-up", "sign_up", "/join", "create-account",
             "createaccount", "users/new", "accounts/new", "registration")
_USER_HINT = ("email", "e-mail", "username", "user", "login", "userid")
_PASS_HINT = ("password", "passwd", "pwd", "pass")
_CREATE_HINT = ("create", "/new", "/add", "upload", "compose", "/post", "project", "topic",
                "article", "store", "/save", "comment", "note", "task", "item")


def _marker() -> str:
    return "owl" + secrets.token_hex(4)


def _form_fields(html: str, action: str) -> dict[str, str]:
    forms = re.findall(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S)
    if not forms:
        return {}
    tail = action.split("/")[-1].split("?")[0]
    body = next((b for a, b in forms if tail and tail in a), forms[0][1])
    out: dict[str, str] = {}
    for tag in _INPUT.findall(body):
        a = {k.lower(): v for k, v in _ATTR.findall(tag)}
        name = a.get("name")
        if not name or (a.get("type") or "text").lower() in ("submit", "button", "image", "reset", "file"):
            continue
        out[name] = a.get("value", "")
    for attrs in _TEXTAREA.findall(body):
        a = {k.lower(): v for k, v in _ATTR.findall(attrs)}
        if a.get("name"):
            out.setdefault(a["name"], "")
    return out


def _fill(name: str, marker: str) -> str:
    n = name.lower()
    if any(k in n for k in ("email", "e-mail")):
        return f"{marker}@example.test"
    if any(k in n for k in ("user", "login")) and "confirm" not in n:
        return marker
    if any(k in n for k in _PASS_HINT):
        return f"Owl_{marker}_9!"
    if any(k in n for k in ("url", "link", "website")):
        return "https://example.test/"
    if any(k in n for k in ("number", "qty", "quantity", "amount", "age", "price", "count")):
        return "1"
    return f"owlforge test {marker}"


def _get(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}) or {}
    except Exception:
        return {}


def _post(sandbox, url, body, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return sandbox.http_request("POST", url, headers=h, body=body, follow_redirects=False) or {}
    except Exception:
        return {}


def _session_cookie(resp: dict) -> dict:
    """Build a Cookie header from any session-ish Set-Cookie on the response."""
    pairs = []
    for sc in resp.get("set_cookie", []) or []:
        head = sc.split(";", 1)[0].strip()
        if "=" in head:
            name = head.split("=", 1)[0].lower()
            if any(k in name for k in ("session", "sess", "sid", "auth", "token", "connect")):
                pairs.append(head)
    return {"Cookie": "; ".join(pairs)} if pairs else {}


# ---- registration -----------------------------------------------------------------------
def register_account(inventory, sandbox, target,
                     log: Callable[[str], None] = lambda m: None) -> dict | None:
    """Find a registration form, create a marker account, and return a new identity
    ({label, role, headers}) when the app auto-starts a session on sign-up. None otherwise."""
    if sandbox is None:
        return None
    cands = []
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST" or it.get("source") not in ("form", "browser-form"):
            continue
        url = (it.get("url") or "").lower()
        params = [p.lower() for p in (it.get("params") or [])]
        has_user = any(any(u in p for u in _USER_HINT) for p in params)
        has_pass = any(any(x in p for x in _PASS_HINT) for p in params)
        looks_reg = any(h in url for h in _REG_HINT) or (
            has_user and has_pass and any("confirm" in p or "repeat" in p for p in params))
        if looks_reg:
            cands.append(it)
    for it in cands[:3]:
        url = it["url"]
        fields = _form_fields(_get(sandbox, url, None).get("body", "") or "", url)
        for p in (it.get("params") or []):
            fields.setdefault(p, "")
        if not any(any(x in n.lower() for x in _PASS_HINT) for n in fields):
            continue
        marker = _marker()
        username = None
        for name in list(fields):
            fields[name] = _fill(name, marker)
            n = name.lower()
            if any(u in n for u in _USER_HINT) and "confirm" not in n and username is None:
                username = fields[name]
        resp = _post(sandbox, url, urlencode(fields), None)
        status = int(resp.get("status") or 0)
        if status not in (200, 301, 302, 303):
            continue
        headers = _session_cookie(resp)
        if headers:
            log(f"seed: registered a throwaway account ({username}) and started a session")
            return {"label": "owlforge-registered", "role": "user", "headers": headers}
        log(f"seed: registered ({username}) but no auto-session — login step needed (skipped)")
    return None


# ---- create / seed objects --------------------------------------------------------------
def seed_objects(inventory, sandbox, session_headers, target,
                 log: Callable[[str], None] = lambda m: None, cap: int = 5) -> list[dict]:
    """Create a few marker objects via state-changing forms and capture the identifier the
    app returns (a redirect Location or a new id in the response). Returns surface items for
    the created objects (source='seeded'), so access-control/IDOR can test them."""
    if sandbox is None or not session_headers:
        return []
    seen, out = set(), []
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST" or it.get("source") not in ("form", "browser-form"):
            continue
        url = it.get("url", "")
        low = url.lower()
        if any(h in low for h in _REG_HINT) or "login" in low or "logout" in low:
            continue
        if not any(h in low for h in _CREATE_HINT) and not (it.get("params")):
            continue
        key = url
        if not url or key in seen:
            continue
        seen.add(key)
        fields = _form_fields(_get(sandbox, url, session_headers).get("body", "") or "", url)
        for p in (it.get("params") or []):
            fields.setdefault(p, "")
        if not fields:
            continue
        marker = _marker()
        for name in list(fields):
            if not fields[name]:
                fields[name] = _fill(name, marker)
        resp = _post(sandbox, url, urlencode(fields), session_headers)
        status = int(resp.get("status") or 0)
        if status not in (200, 201, 301, 302, 303):
            continue
        hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        loc = hdrs.get("location", "")
        created = urljoin(url, loc) if loc else _id_in_body(resp.get("body", ""), url)
        if created and _looks_like_object(created):
            out.append({"url": created, "method": "GET", "params": [], "source": "seeded",
                        "marker": marker})
            log(f"seed: created a test object -> {created}")
        if len(out) >= cap:
            break
    return out


_ID_PATH = re.compile(r"(/[A-Za-z0-9_\-]+/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{20,}))")


def _id_in_body(body: str, base: str) -> str | None:
    m = _ID_PATH.search(body or "")
    return urljoin(base, m.group(1)) if m else None


def _looks_like_object(url: str) -> bool:
    return bool(re.search(r"/(?:\d+|[0-9a-f]{8}-)", url or "")) or "id=" in (url or "")
