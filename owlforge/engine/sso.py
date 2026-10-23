"""SSO breadth — identify third-party sign-in across many identity providers and flag common
OAuth2 / OIDC misconfigurations, deterministically.

owlforge already CAPTURES an SSO session provider-agnostically (headed noVNC, human-in-the-
loop, reused on later runs). This adds the breadth around that:

* detect_sso — recognises the provider(s) an app offers (Google, Microsoft/Azure AD, Okta,
  Auth0, GitHub, GitLab, Facebook, Apple, LinkedIn, OneLogin, Ping, ADFS, Keycloak, generic
  SAML / OIDC) from the login page's buttons, scripts and links;
* sso_scan — follows the app's sign-in entry points one hop to the OAuth2 authorization
  request and checks it for sound, high-signal flaws: a missing `state` parameter (login /
  callback CSRF) and use of the deprecated implicit flow (access token exposed in the URL).

It only reads the app's own same-origin entry points and the provider URL it redirects to;
it never completes a login or submits credentials. Findings are candidates (the provider
config may defend differently) for a human to confirm.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import parse_qs, urljoin, urlsplit

# provider -> substrings that identify it in page HTML / hrefs / scripts (lower-cased)
_PROVIDERS = {
    "Google": ("accounts.google.com", "/auth/google", "oauth2/v2/auth", "apis.google.com",
               "gsi/client", "g_id_", "sign in with google", "continue with google"),
    "Microsoft": ("login.microsoftonline.com", "login.live.com", "/auth/microsoft", "msal",
                  "azuread", "azure ad", "sign in with microsoft", "continue with microsoft"),
    "Okta": (".okta.com", "/oauth2/default", "oktacdn", "sign in with okta"),
    "Auth0": (".auth0.com", "cdn.auth0.com", "lock.min.js", "sign in with auth0"),
    "GitHub": ("github.com/login/oauth", "/auth/github", "sign in with github",
               "continue with github"),
    "GitLab": ("gitlab.com/oauth", "/auth/gitlab", "sign in with gitlab"),
    "Facebook": ("facebook.com/dialog/oauth", "/auth/facebook", "connect.facebook.net",
                 "sign in with facebook", "continue with facebook"),
    "Apple": ("appleid.apple.com", "/auth/apple", "sign in with apple"),
    "LinkedIn": ("linkedin.com/oauth", "/auth/linkedin", "sign in with linkedin"),
    "OneLogin": (".onelogin.com",),
    "Ping": ("pingidentity.com", "pingone.com"),
    "ADFS": ("/adfs/ls", "adfs/oauth2"),
    "Keycloak": ("/realms/", "/protocol/openid-connect"),
    "SAML": ("samlrequest=", "/saml2/", "/sso/saml", "assertionconsumerservice", "saml2p:"),
    "OIDC": ("/.well-known/openid-configuration", "/connect/authorize"),
}
_ENTRY_HINT = ("oauth", "authorize", "/sso", "saml", "openid", "/auth/", "signin", "sign-in",
               "login/oauth", "connect/authorize", "/idp", "federation")
_HREF = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.I)


def detect_sso(html: str, base_url: str = "") -> list[str]:
    """Return the SSO providers an app's page advertises (sorted, de-duplicated)."""
    low = (html or "").lower()
    found = [name for name, sigs in _PROVIDERS.items() if any(sig in low for sig in sigs)]
    return sorted(set(found))


def _is_authorize(url: str) -> bool:
    low = (url or "").lower()
    return ("response_type=" in low or "/authorize" in low or "/oauth2/v2/auth" in low
            or "/connect/authorize" in low or "oauth/authorize" in low)


def find_authorize_urls(html: str, base_url: str) -> list[str]:
    out, seen = [], set()
    for href in _HREF.findall(html or ""):
        u = urljoin(base_url, href)
        if _is_authorize(u) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def oauth_issues(url: str) -> list[tuple[str, str]]:
    """Sound OAuth2 authorization-request flaws readable from the URL itself."""
    q = parse_qs(urlsplit(url).query)
    if "response_type" not in q:
        return []
    issues = []
    if "state" not in q or not (q.get("state") or [""])[0].strip():
        issues.append(("missing_state", "no `state` parameter in the authorization request"))
    rt = " ".join(q.get("response_type", [])).lower()
    if "token" in rt:
        issues.append(("implicit", f"response_type={rt.strip()} (implicit flow — token in URL)"))
    return issues


def _get(sandbox, url, headers, follow):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}, params=None, body=None,
                                    follow_redirects=follow) or {}
    except Exception:
        return {}


def _loc(resp):
    hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    return hdrs.get("location", "") or ""


def _file(assessment_id, kind, url, detail):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    meta = {
        "missing_state": (
            "OAuth2 authorization request without a 'state' parameter (login/callback CSRF)",
            "An attacker can forge the OAuth callback (login CSRF / forced sign-in, or account "
            "linking to an attacker-controlled identity) because the request carries no "
            "unguessable `state` to bind the callback to the user's session.",
            "Send a cryptographically-random `state` on every authorization request and verify "
            "it on the callback (or use PKCE and verify it)."),
        "implicit": (
            "OAuth2 implicit flow in use (access token exposed in the redirect URL)",
            "The access token is returned in the redirect URL fragment, where it leaks via "
            "browser history, Referer headers and logs. The implicit flow is deprecated.",
            "Use the authorization-code flow with PKCE; do not request tokens via response_type=token."),
    }[kind]
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=meta[0], severity="medium", status="candidate", confidence="medium",
            endpoint=url, method="GET",
            technical_analysis=meta[1] + f" Observed authorization request: {url} ({detail}).",
            proof_of_concept=f"authorization request {url} — {detail}",
            impact="Account takeover or unauthorized sign-in depending on the flow and the "
                   "provider's own defences.",
            remediation=meta[2],
            validation_note="read from the OAuth authorization request URL (no login performed) "
                            "— confirm against the provider's configuration"))
        s.commit()


def sso_scan(assessment_id, inventory, sandbox, target,
             session_headers: dict | None = None,
             log: Callable[[str], None] = lambda m: None, cap: int = 12) -> int:
    """Detect SSO providers and flag OAuth2 authorization-request misconfigurations."""
    if sandbox is None:
        return 0
    # pages to inspect: the target root + any login/auth-ish page in the surface
    pages, seen = [], set()
    if target:
        pages.append(target if "://" in target else "https://" + target)
    for it in inventory or []:
        u = it.get("url") or ""
        if u and (it.get("method") or "GET").upper() == "GET" \
                and any(h in u.lower() for h in ("login", "signin", "sign-in", "/sso", "/auth", "account")):
            pages.append(u)
    pages = [p for p in pages if not (p in seen or seen.add(p))][:6]

    providers, authorize, entry_links = set(), [], []
    for p in pages:
        html = _get(sandbox, p, session_headers, True).get("body", "") or ""
        providers.update(detect_sso(html, p))
        authorize.extend(find_authorize_urls(html, p))
        for href in _HREF.findall(html):
            u = urljoin(p, href)
            if any(h in u.lower() for h in _ENTRY_HINT) and urlsplit(u).netloc == urlsplit(p).netloc:
                entry_links.append(u)
    if providers:
        log(f"sso: detected sign-in provider(s): {', '.join(sorted(providers))}")

    # follow app sign-in entry points ONE hop to the provider's authorization request
    for u in list(dict.fromkeys(entry_links))[:cap]:
        r = _get(sandbox, u, session_headers, False)
        if int(r.get("status") or 0) in (301, 302, 303, 307, 308):
            loc = urljoin(u, _loc(r))
            if _is_authorize(loc):
                authorize.append(loc)
        elif _is_authorize(u):
            authorize.append(u)

    filed, seen_keys = 0, set()
    for url in dict.fromkeys(authorize):
        for kind, detail in oauth_issues(url):
            key = (kind, urlsplit(url).netloc + urlsplit(url).path)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            _file(assessment_id, kind, url, detail)
            log(f"sso: {kind} on OAuth authorization request {urlsplit(url).netloc}")
            filed += 1
    return filed
