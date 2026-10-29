"""Detect HOW a target authenticates, and tell the operator exactly what to supply.

When a run ends up unauthenticated, 'unauth' is unhelpful — the operator wants to know
*why* and *what to pass*. This classifies the login as HTTP-Basic / SSO-OAuth / API-key /
token-SPA / classic-form from a couple of cheap requests, and returns a one-line hint that
names the matching flag (--cred / --session / sso identity). Deterministic, no model.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

RequestFn = Callable[..., dict]

_IDP = ("accounts.google.com", "login.microsoftonline.com", "okta.com", "auth0.com",
        "onelogin.com", "pingidentity", "login.salesforce.com", "/login/oauth",
        "adfs", "keycloak", "/realms/", "cognito", "duosecurity", "login.live.com")
_OAUTH = ("response_type=", "client_id=", "/oauth/authorize", "/openid", "samlrequest",
          "/saml2/", "/saml/", "id_token", "sign in with google", "sign in with microsoft",
          "continue with google", "log in with sso", "single sign-on", "/sso/")
_LOGIN_PATHS = ("/login", "/signin", "/sign-in", "/account/login", "/auth/login", "/users/login")

_HINTS = {
    "http-basic": 'HTTP Basic auth → --session "Authorization: Basic <base64 of user:pass>"',
    "sso-oauth": ("SSO/OAuth login → log in in your own browser, then paste it with "
                  '--session "<copy-as-cURL>" (or add an `sso` identity for interactive capture)'),
    "api-key": 'API key required → --session "X-API-Key: <key>" (or the header the API expects)',
    "token-spa": ('token / SPA login → --cred user:pass (owlforge logs in via the browser and '
                  'captures the token), or --session "Authorization: Bearer <jwt>"'),
    "form": "form login → --cred user:pass (owlforge finds the login form for you)",
    "unknown": ("no login found on common paths; if the app needs auth, grab a session from your "
                'browser with --session "<copy-as-cURL>"'),
}


def _get(request_fn, url):
    try:
        r = request_fn("GET", url) or {}
    except Exception:
        return {}
    return r


def detect_auth_mechanism(target: str, request_fn: RequestFn, login_html: str = "") -> dict:
    """Return {mechanism, idp, hint}. mechanism is one of the _HINTS keys."""
    root = _get(request_fn, target)
    rh = {k.lower(): str(v) for k, v in (root.get("headers") or {}).items()}
    wa = rh.get("www-authenticate", "").lower()
    if wa.startswith(("basic", "digest")) or int(root.get("status") or 0) == 401 and "basic" in wa:
        return {"mechanism": "http-basic", "idp": "", "hint": _HINTS["http-basic"]}

    # gather the login surface: given html, else root + common login paths
    blob = (login_html or "").lower()
    loc = rh.get("location", "").lower()
    blob += " " + loc + " " + (root.get("body") or "").lower()
    host = urlsplit(target).netloc.lower()
    for path in _LOGIN_PATHS:
        page = _get(request_fn, target.rstrip("/") + path)
        ph = {k.lower(): str(v) for k, v in (page.get("headers") or {}).items()}
        blob += " " + ph.get("location", "").lower() + " " + (page.get("body") or "").lower()

    # off-host redirect to a known IdP, or OAuth/SAML markers -> SSO
    idp = next((d for d in _IDP if d in blob and d.lstrip("/") not in host), "")
    if idp or any(m in blob for m in _OAUTH):
        return {"mechanism": "sso-oauth", "idp": idp, "hint": _HINTS["sso-oauth"]}
    if "x-api-key" in blob or "api key" in blob or "apikey" in blob:
        return {"mechanism": "api-key", "idp": "", "hint": _HINTS["api-key"]}
    # token in localStorage / SPA bearer usage
    if ("localstorage" in blob and ("token" in blob or "jwt" in blob)) or "bearer " in blob:
        return {"mechanism": "token-spa", "idp": "", "hint": _HINTS["token-spa"]}
    if "<form" in blob and ("password" in blob or "type=\"password\"" in blob):
        return {"mechanism": "form", "idp": "", "hint": _HINTS["form"]}
    return {"mechanism": "unknown", "idp": "", "hint": _HINTS["unknown"]}
