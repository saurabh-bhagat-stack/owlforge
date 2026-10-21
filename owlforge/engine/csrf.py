"""CSRF token handling.

Two jobs: (1) HANDLE anti-CSRF tokens so owlforge's own authenticated/state-changing
requests succeed even when the token rotates per request — fetch the form, read the
current token, submit it; (2) feed the CSRF specialist, which tests whether a
state-changing action still works with the token omitted/stale/replayed.
"""

from __future__ import annotations

import re
from collections.abc import Callable

RequestFn = Callable[..., dict]

# common anti-CSRF field names (case-insensitive)
_TOKEN_NAMES = (
    "csrfmiddlewaretoken", "authenticity_token", "__requestverificationtoken",
    "csrf_token", "csrf-token", "csrftoken", "_csrf", "csrf",
    "xsrf-token", "xsrf_token", "xsrf", "_token", "anti-forgery", "antiforgery",
)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_RE = re.compile(r'(\w[\w:-]*)\s*=\s*"([^"]*)"')


def _is_token_name(name: str) -> bool:
    n = (name or "").lower()
    return any(t == n or t in n for t in _TOKEN_NAMES)


def extract_token(html: str) -> tuple[str, str] | None:
    """Return (field_name, value) of the first anti-CSRF hidden input in the HTML, or
    None. Also catches a <meta name="csrf-token" content="..."> style token."""
    for tag in _INPUT_RE.findall(html or ""):
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(tag)}
        name = attrs.get("name", "")
        if name and _is_token_name(name) and attrs.get("value"):
            return name, attrs["value"]
    m = re.search(r'<meta[^>]+name=["\'](?:csrf-token|_csrf)["\'][^>]+content=["\']([^"\']+)["\']',
                  html or "", re.I)
    if m:
        return "csrf-token", m.group(1)
    return None


def fresh_token(request_fn: RequestFn, page_url: str) -> tuple[str, str] | None:
    """Fetch the page that renders the form and extract its CURRENT token — call this
    immediately before a state-changing request to handle per-request rotation."""
    try:
        r = request_fn("GET", page_url) or {}
    except Exception:
        return None
    if int(r.get("status") or 0) >= 400:
        return None
    return extract_token(r.get("body") or "")


def with_fresh_token(request_fn: RequestFn, page_url: str, params: dict) -> dict:
    """Return params with the form's current CSRF token merged in (rotation-safe)."""
    out = dict(params or {})
    tok = fresh_token(request_fn, page_url)
    if tok:
        out[tok[0]] = tok[1]
    return out


# --------------------------------------------------------------------------------------
# Deterministic CSRF enforcement probe (auto-files candidate findings).
#
# A state-changing form that ships an anti-CSRF token is only actually protected if the
# server REJECTS a request whose token is wrong. This pass fetches the live form in the
# authenticated session, rebuilds its body with every field intact EXCEPT the token (which
# it corrupts), and replays the request once:
#   * rejected (4xx / CSRF error / bounce to form/login) -> token enforced -> NOT a finding
#     (this path is fully non-destructive: a rejected request changes nothing);
#   * processed like a valid request -> token not validated -> CSRF *candidate* (only the
#     token was changed, so this is high-signal / low-false-positive; filed as candidate
#     because one probe cannot prove the state change was durable without repeating a
#     possibly-harmful action, which we deliberately do not do).
# Only forms that already carry a token field are tested. Generic; no lab-specific logic.
# --------------------------------------------------------------------------------------

import secrets as _secrets  # noqa: E402
from urllib.parse import urlencode  # noqa: E402

_REJECT_SIGNALS = ("csrf", "xsrf", "invalid token", "token mismatch", "token is invalid",
                   "missing token", "verification failed", "forbidden", "not allowed",
                   "invalid request", "bad request", "anti-forgery", "request verification")


def _corrupt(value: str) -> str:
    """Return a same-shape but definitely-different token value."""
    if not value:
        return "owlforge0invalid0csrf"
    first = "0" if value[0] != "0" else "1"
    return first + value[1:]


def _csrf_form_fields(html: str, action: str) -> dict[str, str]:
    """name->value for inputs of the <form> whose action matches `action` (else the first
    form): hidden fields, the token, and any input carrying a default value — enough to
    resubmit the request with only the token altered."""
    forms = re.findall(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S)
    if not forms:
        return {}
    tail = action.split("/")[-1].split("?")[0]
    chosen = next((body for attrs, body in forms if tail and tail in attrs), None)
    if chosen is None:
        chosen = forms[0][1]
    fields: dict[str, str] = {}
    for tag in _INPUT_RE.findall(chosen):
        a = {k.lower(): v for k, v in _ATTR_RE.findall(tag)}
        name = a.get("name")
        if not name or (a.get("type") or "text").lower() in ("submit", "button", "image", "reset", "file"):
            continue
        fields[name] = a.get("value", "")
    return fields


def _csrf_rejected(resp: dict, action: str) -> bool:
    status = int(resp.get("status") or 0)
    body = (resp.get("body") or "").lower()
    hdrs = resp.get("headers") or {}
    loc = (hdrs.get("location") or hdrs.get("Location") or "").lower()
    if status in (400, 401, 403, 409, 419, 422, 440) or status == 0 or status >= 500:
        return True  # explicit rejection, or an error/unreachable -> not a successful bypass
    if any(sig in body for sig in _REJECT_SIGNALS):
        return True
    if 300 <= status < 400 and ("login" in loc or action.split("?")[0].endswith(loc.rstrip("/"))):
        return True
    if "login" in body and "password" in body:
        return True
    return False


def _file_csrf(assessment_id, url, method, token_field, resp):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    status = resp.get("status")
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Cross-site request forgery (anti-CSRF token not enforced)",
            severity="medium", status="candidate", confidence="medium",
            endpoint=url, method=method,
            technical_analysis=(
                f"The form posts an anti-CSRF token field '{token_field}', but a request with "
                f"that token corrupted (every other field intact) was processed normally "
                f"(HTTP {status}) instead of being rejected. The token is therefore not "
                "validated against the session, so a cross-site request can perform this "
                "state-changing action on behalf of a logged-in victim."),
            proof_of_concept=(
                f"{method} {url} with '{token_field}' set to a wrong value -> HTTP {status} "
                "(no CSRF rejection); a valid token is not required."),
            impact="An attacker page can silently trigger this state-changing action for any "
                   "authenticated victim who visits it.",
            remediation="Validate the anti-CSRF token server-side on every state-changing "
                        "request and reject mismatches; set session cookies SameSite=Lax/Strict.",
            validation_note="candidate: a corrupted-token request was not rejected "
                            "(deterministic probe) — confirm the action actually took effect",
            repro_url=url, repro_method=method,
            repro_params={token_field: "<wrong-value>"}))
        s.commit()


def _csrf_safe_req(sandbox, method, url, headers, body=None):
    try:
        return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                    body=body, follow_redirects=False) or {}
    except Exception:
        return {}


def csrf_scan(assessment_id, inventory, sandbox, session_headers,
              log: Callable[[str], None] = lambda m: None) -> int:
    """Probe anti-CSRF enforcement on state-changing token-bearing forms; auto-file a
    candidate where a corrupted token is not rejected. Returns the count filed."""
    if sandbox is None:
        return 0
    seen, forms = set(), []
    for it in inventory or []:
        method = (it.get("method") or "GET").upper()
        if method not in ("POST", "PUT", "PATCH") or it.get("source") not in ("form", "browser-form"):
            continue
        tf = next((p for p in (it.get("params") or []) if _is_token_name(p)), None)
        key = (method, it.get("url"))
        if not tf or not it.get("url") or key in seen:
            continue
        seen.add(key)
        forms.append({"url": it["url"], "method": method, "token_field": tf})
    if not forms:
        log("csrf: no token-bearing state-changing forms to probe")
        return 0

    filed = tested = 0
    for f in forms[:12]:
        url, method, tf = f["url"], f["method"], f["token_field"]
        page = _csrf_safe_req(sandbox, "GET", url, session_headers)
        fields = _csrf_form_fields(page.get("body") or "", url)
        if tf not in fields or not fields.get(tf):
            continue  # could not recover a live token -> cannot run the sound test
        tested += 1
        body = dict(fields)
        body[tf] = _corrupt(fields[tf])
        h = dict(session_headers or {})
        h["Content-Type"] = "application/x-www-form-urlencoded"
        resp = _csrf_safe_req(sandbox, method, url, h, body=urlencode(body))
        if _csrf_rejected(resp, url):
            continue
        _file_csrf(assessment_id, url, method, tf, resp)
        filed += 1

    if filed:
        log(f"csrf: {filed} endpoint(s) accepted a corrupted token (candidate CSRF)")
    elif tested:
        log(f"csrf: anti-CSRF token enforced on {tested} tested form(s)")
    else:
        log("csrf: could not recover a live token on the candidate forms")
    return filed
