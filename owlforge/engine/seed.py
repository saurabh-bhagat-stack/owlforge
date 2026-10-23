"""Stateful seeding — owlforge behaves like a tester: if the app lets you register, it
makes a throwaway account (logging in afterwards if sign-up doesn't auto-start a session);
if it lets you create/upload things, it creates one — via an HTML form, a JSON API body, or
a multipart upload — captures the identifier the app hands back, and feeds that to
access-control testing so IDOR/BOLA/mass-assignment can be checked on data owlforge created.

Part of the deep authenticated pipeline (no flag). Writes are benign and marker-labelled
(`owlforge test <rand>`); it only ADDS test entries — it never edits or deletes anyone
else's data. On an authorized engagement this is normal tester behaviour.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from urllib.parse import urlencode, urljoin

_INPUT = re.compile(r"<input\b[^>]*>", re.I)
_TEXTAREA = re.compile(r"<textarea\b([^>]*)>", re.I)
_ATTR = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'<>`]+))""")


def _attrs(s: str) -> dict[str, str]:
    """Parse HTML tag attributes, tolerating double-quoted, single-quoted and unquoted values."""
    out: dict[str, str] = {}
    for name, dq, sq, uq in _ATTR.findall(s or ""):
        out[name.lower()] = dq or sq or uq or ""
    return out
_FILE_INPUT = re.compile(r'<input\b[^>]*type\s*=\s*["\']?file["\']?[^>]*>', re.I)
_NAME = re.compile(r'name\s*=\s*["\']?([\w\[\]-]+)', re.I)

_REG_HINT = ("register", "signup", "sign-up", "sign_up", "/join", "create-account",
             "createaccount", "users/new", "accounts/new", "registration")
_LOGIN_HINT = ("login", "signin", "sign-in", "sign_in", "/auth", "sessions")
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
        a = _attrs(tag)
        name = a.get("name")
        if not name or (a.get("type") or "text").lower() in ("submit", "button", "image", "reset", "file"):
            continue
        out[name] = a.get("value", "")
    for attrs in _TEXTAREA.findall(body):
        a = _attrs(attrs)
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


def _post_json(sandbox, url, obj, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = "application/json"
        return sandbox.http_request("POST", url, headers=h, body=json.dumps(obj),
                                    follow_redirects=False) or {}
    except Exception:
        return {}


def _multipart(fields: dict, file_field: str, filename: str, content: str, ctype: str):
    b = "----owl" + secrets.token_hex(8)
    out = []
    for k, v in (fields or {}).items():
        out.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n')
    out.append(f'--{b}\r\nContent-Disposition: form-data; name="{file_field}"; '
               f'filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n{content}\r\n')
    out.append(f"--{b}--\r\n")
    return "".join(out), f"multipart/form-data; boundary={b}"


def _post_multipart(sandbox, url, body, ctype, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = ctype
        return sandbox.http_request("POST", url, headers=h, body=body, follow_redirects=False) or {}
    except Exception:
        return {}


def _form_html(sandbox, url, headers) -> str:
    """Fetch a page's HTML for form parsing. If the raw response has no form (a JS-rendered
    SPA) and the sandbox can render, fall back to the browser-rendered DOM so seeding sees the
    real form fields. JSON/API responses are returned as-is (no wasteful render)."""
    raw = _get(sandbox, url, headers).get("body", "") or ""
    low = raw.lower()
    if "<form" in low or _INPUT.search(raw):
        return raw
    if raw.strip()[:1] in "{[":
        return raw
    if hasattr(sandbox, "render"):
        try:
            d = sandbox.render(url, headers=headers or None) or {}
            dom = d.get("html", "") or ""
            if "<form" in dom.lower() or _INPUT.search(dom):
                return dom
        except Exception:
            pass
    return raw


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


# ---- registration (+ two-step login) ----------------------------------------------------
def _login(inventory, sandbox, identifiers, password,
           log: Callable[[str], None] = lambda m: None) -> dict:
    """Log in with just-registered creds when sign-up did not auto-start a session.
    Returns session headers or {}."""
    if not password:
        return {}
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST" or it.get("source") not in ("form", "browser-form"):
            continue
        url = it.get("url") or ""
        low = url.lower()
        if any(h in low for h in _REG_HINT):
            continue
        params = [p.lower() for p in (it.get("params") or [])]
        has_pass = any(any(x in p for x in _PASS_HINT) for p in params)
        if not (any(h in low for h in _LOGIN_HINT) or has_pass):
            continue
        fields = _form_fields(_form_html(sandbox, url, None), url)
        for p in (it.get("params") or []):
            fields.setdefault(p, "")
        if not any(any(x in n.lower() for x in _PASS_HINT) for n in fields):
            continue
        for ident in (list(identifiers) or [""]):
            body = dict(fields)
            mk = _marker()
            for n in list(body):
                nl = n.lower()
                if any(x in nl for x in _PASS_HINT):
                    body[n] = password
                elif any(x in nl for x in _USER_HINT) and "confirm" not in nl:
                    body[n] = ident
                elif not body[n]:
                    body[n] = _fill(n, mk)
            resp = _post(sandbox, url, urlencode(body), None)
            if int(resp.get("status") or 0) in (200, 301, 302, 303):
                sess = _session_cookie(resp)
                if sess:
                    return sess
    return {}


def register_account(inventory, sandbox, target,
                     log: Callable[[str], None] = lambda m: None) -> dict | None:
    """Find a registration form, create a marker account, and return a new identity
    ({label, role, headers}). If sign-up doesn't auto-start a session, log in with the new
    credentials (two-step). None if no session could be established."""
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
        fields = _form_fields(_form_html(sandbox, url, None), url)
        for p in (it.get("params") or []):
            fields.setdefault(p, "")
        if not any(any(x in n.lower() for x in _PASS_HINT) for n in fields):
            continue
        marker = _marker()
        username = None
        identifiers: list[str] = []
        password = ""
        for name in list(fields):
            fields[name] = _fill(name, marker)
            n = name.lower()
            if any(x in n for x in _PASS_HINT) and "confirm" not in n and not password:
                password = fields[name]
            if any(u in n for u in _USER_HINT) and "confirm" not in n:
                identifiers.append(fields[name])
                if username is None:
                    username = fields[name]
        resp = _post(sandbox, url, urlencode(fields), None)
        status = int(resp.get("status") or 0)
        if status not in (200, 301, 302, 303):
            continue
        headers = _session_cookie(resp)
        if headers:
            log(f"seed: registered a throwaway account ({username}) and started a session")
            return {"label": "owlforge-registered", "role": "user", "headers": headers}
        sess = _login(inventory, sandbox, identifiers, password, log)
        if sess:
            log(f"seed: registered ({username}) and logged in (two-step)")
            return {"label": "owlforge-registered", "role": "user", "headers": sess}
        log(f"seed: registered ({username}) but could not establish a session")
    return None


# ---- create / seed objects --------------------------------------------------------------
def _is_api(it: dict, url: str) -> bool:
    low = url.lower()
    return it.get("source") in ("api-spec", "graphql") or "/api/" in low or "/graphql" in low


def _create_multipart(sandbox, url, html, fields, marker, session_headers):
    fi = _FILE_INPUT.search(html)
    nm = _NAME.search(fi.group(0)) if fi else None
    field = nm.group(1) if nm else "file"
    data = {n: (fields[n] or _fill(n, marker)) for n in fields}
    body, ct = _multipart(data, field, f"owl{marker}.txt", f"owlforge test {marker}", "text/plain")
    return _post_multipart(sandbox, url, body, ct, session_headers)


def seed_objects(inventory, sandbox, session_headers, target,
                 log: Callable[[str], None] = lambda m: None, cap: int = 5) -> list[dict]:
    """Create a few marker objects via state-changing endpoints — HTML forms, JSON API
    bodies, or multipart uploads — and capture the identifier the app returns (a redirect
    Location, an id in the body, or a JSON id). Returns surface items (source='seeded')."""
    if sandbox is None or not session_headers:
        return []
    seen, out = set(), []
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST" or it.get("source") not in (
                "form", "browser-form", "api-spec", "graphql"):
            continue
        url = it.get("url", "")
        low = url.lower()
        if any(h in low for h in _REG_HINT) or "login" in low or "logout" in low:
            continue
        if not any(h in low for h in _CREATE_HINT) and not it.get("params"):
            continue
        if not url or url in seen:
            continue
        seen.add(url)
        html = _form_html(sandbox, url, session_headers)
        fields = _form_fields(html, url)
        for p in (it.get("params") or []):
            fields.setdefault(p, "")
        marker = _marker()
        if _FILE_INPUT.search(html):
            resp = _create_multipart(sandbox, url, html, fields, marker, session_headers)
        elif _is_api(it, url):
            obj = {p: _fill(p, marker) for p in (it.get("params") or [])}
            for n in fields:
                obj.setdefault(n, fields[n] or _fill(n, marker))
            if not obj:
                continue
            resp = _post_json(sandbox, url, obj, session_headers)
        else:
            if not fields:
                continue
            for name in list(fields):
                if not fields[name]:
                    fields[name] = _fill(name, marker)
            resp = _post(sandbox, url, urlencode(fields), session_headers)
        status = int(resp.get("status") or 0)
        if status not in (200, 201, 301, 302, 303):
            continue
        hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        loc = hdrs.get("location", "")
        body = resp.get("body", "") or ""
        created = urljoin(url, loc) if loc else _id_in_body(body, url)
        json_created = None if created else _id_from_json(body, url)
        final = created or json_created
        if final and (json_created or _looks_like_object(final)):
            out.append({"url": final, "method": "GET", "params": [], "source": "seeded",
                        "marker": marker})
            log(f"seed: created a test object -> {final}")
        if len(out) >= cap:
            break
    return out


_ID_PATH = re.compile(r"(/[A-Za-z0-9_\-]+/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{20,}))")
_JSON_ID = re.compile(r'["\'](?:id|_id|uuid|slug|pk)["\']\s*:\s*["\']?([A-Za-z0-9_-]{1,64})', re.I)


def _id_in_body(body: str, base: str) -> str | None:
    m = _ID_PATH.search(body or "")
    return urljoin(base, m.group(1)) if m else None


def _id_from_json(body: str, base: str) -> str | None:
    m = _JSON_ID.search(body or "")
    return base.rstrip("/") + "/" + m.group(1) if m else None


def _looks_like_object(url: str) -> bool:
    return bool(re.search(r"/(?:\d+|[0-9a-f]{8}-)", url or "")) or "id=" in (url or "")


# ---- GraphQL mutation seeding -----------------------------------------------------------
_GQL_PATHS = ("/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/query", "/gql")
_GQL_CREATE = ("create", "add", "new", "register", "post", "insert", "signup", "save", "submit")
_GQL_SCALARS = ("String", "Int", "Float", "Boolean", "ID")
_INTROSPECT_MUT = ("query{__schema{mutationType{fields{name args{name type{kind name "
                   "ofType{kind name ofType{kind name}}}}}}}}")


def _gql_post(sandbox, url, query, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = "application/json"
        return sandbox.http_request("POST", url, body=json.dumps({"query": query}), headers=h) or {}
    except Exception:
        return {}


def _gql_endpoints(inventory, target):
    eps = [it["url"] for it in inventory or [] if it.get("source") == "graphql" and it.get("url")]
    eps = list(dict.fromkeys(eps))
    if eps:
        return eps
    from urllib.parse import urlsplit, urlunsplit
    if not target:
        return []
    b = urlsplit(target)
    return [urlunsplit((b.scheme, b.netloc, pth, "", "")) for pth in _GQL_PATHS]


def _gql_base_type(t: dict):
    while t and t.get("ofType"):
        t = t["ofType"]
    return t or {}


def _gql_literal(scalar: str, marker: str) -> str:
    if scalar in ("Int", "Float"):
        return "1"
    if scalar == "Boolean":
        return "false"
    return json.dumps(f"owlforge test {marker}" if scalar != "ID" else marker)


_INTROSPECT_INPUT_HEAD = '{__type(name:"'
_INTROSPECT_INPUT_TAIL = '"){inputFields{name type{kind name ofType{kind name ofType{kind name}}}}}}'


def _gql_input_literal(sandbox, url, type_name, headers, marker, depth=0) -> str:
    """Build a GraphQL input-object literal for an INPUT_OBJECT arg by introspecting its
    fields and filling scalars (recurses one level into nested input objects)."""
    if depth > 1 or not type_name:
        return ""
    q = _INTROSPECT_INPUT_HEAD + type_name + _INTROSPECT_INPUT_TAIL
    r = _gql_post(sandbox, url, q, headers)
    try:
        ifs = json.loads(r.get("body", "") or "").get("data", {}).get("__type", {}).get("inputFields") or []
    except Exception:
        return ""
    parts = []
    for fld in ifs:
        base = _gql_base_type(fld.get("type") or {})
        if base.get("name") in _GQL_SCALARS:
            parts.append(f'{fld["name"]}:{_gql_literal(base["name"], marker)}')
        elif base.get("kind") == "INPUT_OBJECT" and base.get("name"):
            sub = _gql_input_literal(sandbox, url, base["name"], headers, marker, depth + 1)
            if sub:
                parts.append(f'{fld["name"]}:{sub}')
    return "{" + ", ".join(parts) + "}" if parts else ""


def _gql_read_field(mutation_name: str) -> str:
    """Convention: createPost -> post, addUser -> user (a plausible query field to read back)."""
    n = mutation_name or ""
    for pre in ("create", "add", "new", "insert", "signup", "register", "save", "submit", "make"):
        if n.lower().startswith(pre):
            n = n[len(pre):]
            break
    return (n[0].lower() + n[1:]) if n else mutation_name


def graphql_seed_objects(inventory, sandbox, session_headers, target,
                         log: Callable[[str], None] = lambda m: None, cap: int = 3) -> list[dict]:
    """If a GraphQL endpoint exposes introspection, create an object via a create-ish mutation
    whose required args are all scalars, and capture the returned id. Returns seeded items.

    Note: GraphQL objects have no per-object REST URL, so these feed the app model and the
    GraphQL / business-logic specialists rather than the REST access-control passes."""
    if sandbox is None or not session_headers:
        return []
    out: list[dict] = []
    for url in _gql_endpoints(inventory, target)[:3]:
        intro = _gql_post(sandbox, url, _INTROSPECT_MUT, session_headers)
        body = intro.get("body", "") or ""
        if "mutationType" not in body:
            continue
        try:
            mt = json.loads(body).get("data", {}).get("__schema", {}).get("mutationType") or {}
        except Exception:
            continue
        for f in (mt.get("fields") or []):
            name = f.get("name", "")
            if not any(h in name.lower() for h in _GQL_CREATE):
                continue
            marker = _marker()
            arglits, ok = [], True
            for a in (f.get("args") or []):
                base = _gql_base_type(a.get("type") or {})
                required = (a.get("type") or {}).get("kind") == "NON_NULL"
                if base.get("name") in _GQL_SCALARS:
                    arglits.append(f'{a["name"]}:{_gql_literal(base["name"], marker)}')
                elif base.get("kind") == "INPUT_OBJECT" and base.get("name"):
                    lit = _gql_input_literal(sandbox, url, base["name"], session_headers, marker)
                    if lit:
                        arglits.append(f'{a["name"]}:{lit}')
                    elif required:
                        ok = False
                        break
                elif required:
                    ok = False
                    break
            if not ok:
                continue
            argstr = ("(" + ", ".join(arglits) + ")") if arglits else ""
            for sel in ("{id}", "{id __typename}", "{__typename}"):
                r = _gql_post(sandbox, url, f"mutation{{{name}{argstr}{sel}}}", session_headers)
                rb = r.get("body", "") or ""
                try:
                    data = json.loads(rb).get("data") or {}
                except Exception:
                    data = {}
                node = data.get(name) if isinstance(data, dict) else None
                if node is not None:
                    rid = node.get("id") if isinstance(node, dict) else None
                    out.append({"url": url, "method": "POST", "params": [], "source": "seeded-graphql",
                                "marker": marker, "graphql": f"mutation {name}", "object_id": rid,
                                "endpoint": url, "read_field": _gql_read_field(name)})
                    log(f"seed: created a GraphQL object via {name}() (id={rid})")
                    break
            if len(out) >= cap:
                break
        if len(out) >= cap:
            break
    return out
