"""SPA-aware self-registration: create a throwaway account through a JSON register API.

The classic seeder (seed.register_account) looks for a server-rendered <form> and submits
form-encoded data — blind to a modern SPA, whose sign-up is a JSON API (POST /api/Users,
/api/users/basic, …) with no HTML form. So on an SPA it finds nothing and the scan silently
runs anonymous. register_json_spa fills that gap: it discovers the register endpoint (from the
OpenAPI spec when the app serves one, else well-known paths / recon), builds a JSON body that
satisfies the required fields (spec-driven, with sensible placeholders), POSTs it, then obtains
a session — straight from the register response (cookie / token) or by logging the new account
in through the real browser (SPA) or a JSON login API. Returns an identity dict or None.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from urllib.parse import urlsplit

# register endpoints by path (the sign-up API rarely appears in the crawl — it's an XHR)
_API_REGISTER_PATHS = ("/api/users/basic", "/api/Users", "/api/users", "/api/user",
                       "/api/auth/register", "/api/auth/signup", "/api/register",
                       "/api/v1/register", "/api/v1/auth/register", "/api/signup",
                       "/api/sign-up", "/api/account/register", "/rest/user", "/users",
                       "/register", "/signup")
# where an app commonly serves its OpenAPI/Swagger document
_OPENAPI_PATHS = ("/swagger-json", "/openapi.json", "/api-json", "/v3/api-docs", "/api-docs",
                  "/swagger.json", "/api/swagger.json", "/api-docs/swagger.json",
                  "/api/openapi.json", "/swagger/v1/swagger.json")
# register sub-paths tried under each discovered gateway/microservice prefix (relative)
_REG_SUBPATHS = ("api/auth/signup", "api/auth/register", "api/signup", "api/register",
                 "api/users", "api/user", "api/v1/auth/register", "api/v1/signup",
                 "auth/signup", "auth/register", "signup", "register", "users")
# common microservice/gateway path segments (app-specific ones come from the crawled surface)
_GATEWAY_SEGS = ("identity", "auth", "authentication", "user", "users", "account", "accounts",
                 "api", "gateway", "apigateway", "core", "backend", "services", "service",
                 "main", "app", "web", "v1", "v2")
_REG_HINT = ("register", "signup", "sign-up", "sign_up", "/users", "/user", "create-account",
             "/join", "/accounts")


def _marker() -> str:
    return secrets.token_hex(4)


def _phone(marker: str) -> str:
    """A unique 10-digit phone number derived from the marker (apps like crAPI require the
    number to be unique, so a fixed placeholder fails every registration after the first)."""
    return ("9" + str(int(marker, 16))).ljust(10, "0")[:10]


def _req(sandbox, method, url, *, headers=None, body=None):
    try:
        return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                    body=body, follow_redirects=False) or {}
    except TypeError:
        try:
            return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                        body=body) or {}
        except Exception:
            return {}
    except Exception:
        return {}


def _post_json(sandbox, url, obj):
    return _req(sandbox, "POST", url, headers={"Content-Type": "application/json"},
               body=json.dumps(obj))


def _json(resp):
    try:
        return json.loads(resp.get("body") or "")
    except Exception:
        return None


def _fetch_openapi(sandbox, origin) -> dict | None:
    for p in _OPENAPI_PATHS:
        doc = _json(_req(sandbox, "GET", origin + p))
        if isinstance(doc, dict) and ("paths" in doc or "swagger" in doc or "openapi" in doc):
            return doc
    return None


def _deref(spec, node):
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return {}
        cur = spec
        for part in ref[2:].split("/"):
            cur = (cur or {}).get(part, {})
        node = cur
        seen += 1
    return node if isinstance(node, dict) else {}


def _value_for(name, prop, spec, marker, email, password, depth=0):
    """A plausible value for one property, by name then type (spec-driven, recursive)."""
    prop = _deref(spec, prop) if isinstance(prop, dict) else {}
    n = (name or "").lower()
    t = prop.get("type")
    if "enum" in prop and prop["enum"]:
        return prop["enum"][0]
    if any(k in n for k in ("email", "e-mail")):
        return email
    if "password" in n or n in ("pass", "pwd"):
        return password
    if any(k in n for k in ("firstname", "first_name", "givenname")):
        return "Owl"
    if any(k in n for k in ("lastname", "last_name", "surname", "familyname")):
        return "Forge"
    if n in ("username", "user", "login", "nickname", "handle"):
        return f"owl{marker}"
    if n in ("name", "fullname", "displayname"):
        return "Owl Forge"
    if "phone" in n or "mobile" in n or n == "number":
        return _phone(marker)
    if "card" in n:
        return "0000000000000000"
    if "company" in n or "organization" in n or "org" in n:
        return "owlforge"
    if n.endswith("url") or n == "url" or "website" in n:
        return "https://owlforge.test"
    if "answer" in n:
        return "owl"
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    if t == "array":
        item = _value_for(name[:-1] if name.endswith("s") else name,
                          prop.get("items", {}), spec, marker, email, password, depth + 1)
        return [item]
    if t == "object" or prop.get("properties"):
        if depth > 4:
            return {}
        return _build_object(prop, spec, marker, email, password, depth + 1)
    if prop.get("format") == "email":
        return email
    return f"owl{marker}"


def _build_object(schema, spec, marker, email, password, depth=0) -> dict:
    schema = _deref(spec, schema)
    props = schema.get("properties") or {}
    required = schema.get("required") or list(props.keys())
    out = {}
    for name in props:
        if name in required or len(out) < 12:         # fill required (+ a few optionals)
            out[name] = _value_for(name, props[name], spec, marker, email, password, depth)
    return out


def _request_schema(spec, op) -> dict | None:
    body = (op or {}).get("requestBody") or {}
    content = (body.get("content") or {}).get("application/json") or {}
    sch = content.get("schema")
    return _deref(spec, sch) if sch else None


def _spec_register_targets(spec, origin):
    """(url, schema) for POST operations whose path looks like a sign-up."""
    out = []
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for method in ("post", "put"):
            if method in ops and any(h in path.lower() for h in _REG_HINT):
                out.append((origin + path, _request_schema(spec, ops[method])))
    return out


def _bearer(resp):
    from owlforge.engine.authbypass import _JWT, _TOKEN_KEY
    body = resp.get("body") or ""
    m = _JWT.search(body)
    if m:
        return m.group(0)
    data = _json(resp)
    if isinstance(data, dict):
        for k in ("token", "accessToken", "access_token", "jwt", "id_token"):
            v = data.get(k)
            if isinstance(v, str) and len(v) >= 12:
                return v
        auth = data.get("authentication")
        if isinstance(auth, dict) and isinstance(auth.get("token"), str):
            return auth["token"]
    if _TOKEN_KEY.search(body):
        m = _JWT.search(body)
        return m.group(0) if m else None
    return None


def _session_from_response(resp, target) -> dict:
    hdrs = {}
    try:
        from owlforge.engine.seed import _session_cookie
        hdrs.update(_session_cookie(resp) or {})
    except Exception:
        pass
    tok = _bearer(resp)
    if tok:
        hdrs["Authorization"] = f"Bearer {tok}"
    return hdrs


def _login_new_account(sandbox, target, email, password, log, register_url="") -> dict:
    """Get a session for a just-created account: a login URL derived from the register URL
    (signup->login, same gateway prefix) first, then SPA browser login, then generic JSON APIs."""
    import re as _re
    for a in ("signup", "sign-up", "registration", "register"):
        if register_url and a in register_url.lower():
            login_url = _re.sub(a, "login", register_url, count=1, flags=_re.I)
            for uf in ("email", "user", "username"):
                resp = _post_json(sandbox, login_url, {uf: email, "password": password})
                if int(resp.get("status") or 0) in (200, 201):
                    hdrs = _session_from_response(resp, target)
                    if hdrs:
                        return hdrs
            break
    try:
        from owlforge.engine.authspec import _spa_login_probe
        _url, hdrs = _spa_login_probe(sandbox, target, {"user": email, "password": password},
                                      log=lambda m: None)
        if hdrs:
            return hdrs
    except Exception:
        pass
    from owlforge.engine.authbypass import _API_LOGIN_PATHS
    u = urlsplit(target)
    origin = f"{u.scheme}://{u.netloc}"
    for p in _API_LOGIN_PATHS:
        for uf in ("email", "user", "username"):
            resp = _post_json(sandbox, origin + p, {uf: email, "password": password})
            if int(resp.get("status") or 0) in (200, 201):
                hdrs = _session_from_response(resp, target)
                if hdrs:
                    return hdrs
    return {}


# path segments that are never an auth gateway (static assets, health, docs) — skip them so
# their register combos do not crowd out the real prefix under the candidate cap
_NON_AUTH_SEGS = frozenset({"static", "images", "image", "img", "assets", "asset", "css", "js",
    "fonts", "font", "media", "public", "health", "healthz", "healthcheck", "favicon", "robots",
    "manifest", "sitemap", "docs", "swagger", "chatbot"})


def _live_prefixes(inventory, sandbox, origin) -> list[str]:
    """Modern API apps route the auth service behind a prefix (crAPI: /identity/api/auth/signup)
    that is not a literal in the JS. Probe candidate top-level segments — the common-microservice
    list FIRST (auth-relevant, so /identity is tried before noisy ones), then crawled-surface
    segments — and keep the ones that resolve. Priority order matters: register sub-paths are
    generated per prefix, so an auth prefix must come before health/static/etc."""
    ordered: list[str] = list(_GATEWAY_SEGS)
    for it in inventory or []:
        path = urlsplit(it.get("url") or "").path.strip("/")
        if path:
            s0 = path.split("/")[0].lower()
            if s0.isalpha() and 2 <= len(s0) <= 24 and s0 not in ordered:
                ordered.append(s0)
    live = []
    for seg in ordered:
        if seg in _NON_AUTH_SEGS:
            continue
        try:
            st = int(_req(sandbox, "GET", f"{origin}/{seg}").get("status") or 0)
        except Exception:
            st = 0
        if st and st != 404:                       # exists (200/301/401/403/...)
            live.append(seg)
        if len(live) >= 10:
            break
    return live


def register_json_spa(inventory, sandbox, target,
                      log: Callable[[str], None] = lambda m: None) -> dict | None:
    """Register a throwaway account via a JSON API and return an identity, or None."""
    if sandbox is None or not hasattr(sandbox, "http_request"):
        return None
    u = urlsplit(target)
    origin = f"{u.scheme}://{u.netloc}"
    marker = _marker()
    email = f"owl{marker}@owlforge.test"
    password = f"Owl{marker}Aa1!"

    spec = _fetch_openapi(sandbox, origin)
    targets: list[tuple[str, dict | None]] = []
    seen = set()

    def _add(url, schema):
        if url and url not in seen:
            seen.add(url)
            targets.append((url, schema))

    if spec:
        for url, schema in _spec_register_targets(spec, origin):
            _add(url, schema)
    for it in inventory or []:                      # register-ish endpoints seen in recon
        url = it.get("url") or ""
        if (it.get("method") or "GET").upper() in ("POST", "PUT") and any(
                h in url.lower() for h in _REG_HINT):
            _add(url, None)
    for p in _API_REGISTER_PATHS:                   # well-known register paths
        _add(origin + p, None)
    for seg in _live_prefixes(inventory, sandbox, origin):   # microservice-prefixed register APIs
        for sub in _REG_SUBPATHS:
            _add(f"{origin}/{seg}/{sub}", None)

    # a generous heuristic body for endpoints with no schema
    heuristic = {"email": email, "password": password, "passwordRepeat": password,
                 "repeatPassword": password, "password_confirmation": password,
                 "username": f"owl{marker}", "user": email, "name": "Owl Forge",
                 "firstName": "Owl", "lastName": "Forge", "company": "owlforge",
                 "securityAnswer": "owl", "phoneNumber": _phone(marker),
                 "number": _phone(marker), "phone": _phone(marker), "mobile": _phone(marker)}

    for url, schema in targets[:48]:
        body = _build_object(schema, spec, marker, email, password) if schema else heuristic
        if "email" not in body and "user" not in body:
            continue
        resp = _post_json(sandbox, url, body)
        if int(resp.get("status") or 0) not in (200, 201):
            continue
        hdrs = _session_from_response(resp, target) or _login_new_account(
            sandbox, target, email, password, log, register_url=url)
        if hdrs:
            log(f"registered a throwaway account ({email}) via JSON API {url} and got a session")
            return {"label": "owlforge-registered", "role": "user", "headers": hdrs,
                    "login": {"url": url, "user": email, "password": password,
                              "user_field": "email", "pass_field": "password"}}
        log(f"registered ({email}) via {url} but could not establish a session")
        continue
    return None
