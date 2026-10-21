"""Password-reset / OAuth-adjacent checks.

Password-reset poisoning: many apps build the reset link from the request Host header, so a
spoofed Host sends the victim a reset link pointing at an attacker domain (account takeover).
We can't read the email, so this is filed as a CANDIDATE: we POST a reset request with a
spoofed Host and flag it when the host is reflected or the reset is accepted — a human then
confirms the email. OAuth redirect_uri open-redirect is already covered by the open-redirect
probe; state/PKCE flaws are app-specific and left to manual review.
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable
from urllib.parse import urlencode, urlsplit, urlunsplit

_RESET_HINTS = ("forgot", "reset", "recover", "forgot-password", "forgot_password",
                "reset-password", "reset_password", "lostpassword", "password/reset")
_RESET_PATHS = ("/forgot-password", "/forgot", "/password/reset", "/reset-password",
                "/account/recover", "/users/password", "/auth/forgot")
_EMAIL_FIELDS = ("email", "username", "user", "login", "mail", "emailAddress")
_EVIL = "owl-pwreset.example"


def _reset_endpoints(inventory, target):
    eps = [it["url"] for it in inventory
           if any(h in (it.get("url") or "").lower() for h in _RESET_HINTS)]
    if not eps and target:
        b = urlsplit(target)
        eps = [urlunsplit((b.scheme, b.netloc, p, "", "")) for p in _RESET_PATHS]
    return list(dict.fromkeys(eps))[:6]


def _file(assessment_id, url, reflected):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Possible password-reset host-header poisoning (account takeover)",
            severity="high" if reflected else "medium",
            status="candidate", confidence="medium" if reflected else "low",
            endpoint=url, method="POST",
            technical_analysis=(f"A password-reset request to {url} with a spoofed "
                                f"Host/X-Forwarded-Host ({_EVIL}) was "
                                + ("reflected into the response" if reflected else "accepted")
                                + ". If the reset email builds its link from the Host header, "
                                "the victim receives an attacker-controlled reset link -> "
                                "account takeover. Verify by inspecting the reset email."),
            proof_of_concept=f"POST {url}  Host: {_EVIL}  -> "
                             + ("host reflected" if reflected else "reset accepted (200)"),
            impact="Account takeover via a poisoned password-reset link.",
            remediation="Build reset links from a fixed, server-configured base URL; never "
                        "trust the Host/X-Forwarded-Host header.",
            validation_note="potential password-reset poisoning — needs manual verification "
                            "(inspect the reset email)"))
        s.commit()


def password_reset_scan(assessment_id, inventory, sandbox, session_headers, target="",
                        log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None:
        return 0
    eps = _reset_endpoints(inventory, target)
    if not eps:
        return 0
    email = f"owl{_secrets.token_hex(3)}@example.com"
    hdrs = {"Host": _EVIL, "X-Forwarded-Host": _EVIL,
            "Content-Type": "application/x-www-form-urlencoded", **(session_headers or {})}
    filed = 0
    for url in eps:
        for field in _EMAIL_FIELDS[:3]:
            try:
                r = sandbox.http_request("POST", url, body=urlencode({field: email}),
                                         headers=hdrs) or {}
            except Exception:
                continue
            status = int(r.get("status") or 0)
            body = r.get("body") or ""
            loc = (r.get("headers") or {}).get("location", "")
            reflected = _EVIL in body or _EVIL in loc
            if reflected or status in (200, 302):
                _file(assessment_id, url, reflected)
                filed += 1
                break   # one hit per endpoint
    if filed:
        log(f"password-reset: {filed} possible host-header poisoning sink(s) (manual verify)")
    return filed
