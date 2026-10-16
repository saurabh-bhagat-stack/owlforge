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
