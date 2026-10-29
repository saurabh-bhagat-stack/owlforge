"""Passive security checks — deterministic, no LLM, near-zero cost.

Harvests issues that need no "hunting": missing/weak security headers, insecure
cookie flags, permissive CORS, version disclosure, directory listing and verbose
error/stack traces. Each becomes a candidate finding (the response itself is the
evidence). Cheap OWASP A02/A05/A06 recall that also hints the active specialists.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC

RequestFn = Callable[..., dict]


@dataclass
class PassiveFinding:
    title: str
    severity: str
    evidence: str
    detail: str
    url: str = ""


_STACK_MARKERS = ("traceback (most recent call last)", "java.lang.", "system.web.",
                  "ora-0", "sqlstate", "stack trace:", "nullpointerexception",
                  "org.springframework", "werkzeug debugger", "fatal error:")
_SESSION_COOKIE = ("session", "sess", "sid", "auth", "token", "jwt", "phpsessid", "jsessionid")
# serialized-object markers: java(b64 rO0AB / ac ed 00 05), php (O:n:"), .NET ViewState, python pickle
_SERIALIZED = ("rO0AB", "__VIEWSTATE", "O:8:\"", "O:4:\"", "a:1:{", "gASV", "\\x80\\x04")


def scan_response(url: str, resp: dict) -> list[PassiveFinding]:
    """Run passive checks against one fetched response."""
    out: list[PassiveFinding] = []
    h = {k.lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
    body = resp.get("body") or ""
    https = url.lower().startswith("https")
    csp = h.get("content-security-policy", "")

    def add(title, sev, evidence, detail):
        out.append(PassiveFinding(title=title, severity=sev, evidence=evidence, detail=detail, url=url))

    if not csp:
        add("Missing Content-Security-Policy", "info", "no content-security-policy header",
            "No CSP — the page has no browser-enforced restriction on script/style/framing sources.")
    if https and "strict-transport-security" not in h:
        add("Missing HSTS", "info", "no strict-transport-security header",
            "HTTPS response without HSTS — allows SSL-strip / downgrade on first visit.")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("Missing X-Content-Type-Options: nosniff", "info",
            f"x-content-type-options={h.get('x-content-type-options', '(absent)')}",
            "Browser MIME-sniffing not disabled — can enable content-type confusion attacks.")
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        add("Clickjacking: no X-Frame-Options / frame-ancestors", "info",
            "no x-frame-options and no CSP frame-ancestors",
            "Page can be framed by any origin — clickjacking exposure.")

    # cookie flags
    raw_cookies = resp.get("headers", {})
    set_cookies = [v for k, v in (raw_cookies or {}).items() if k.lower() == "set-cookie"]
    for sc in set_cookies:
        name = sc.split("=", 1)[0].strip().lower()
        low = sc.lower()
        sessiony = any(s in name for s in _SESSION_COOKIE)
        if https and "secure" not in low:
            add(f"Cookie without Secure flag: {name}", "medium" if sessiony else "low",
                sc[:160], "Cookie set over HTTPS without Secure — may be sent over plaintext.")
        if "httponly" not in low:
            add(f"Cookie without HttpOnly flag: {name}", "medium" if sessiony else "low",
                sc[:160], "Cookie readable by JavaScript — exfiltratable via XSS.")
        if "samesite" not in low:
            add(f"Cookie without SameSite: {name}", "low", sc[:160],
                "No SameSite — cookie sent on cross-site requests (CSRF exposure).")
        if sessiony:
            # a session cookie should be session-scoped (no Expires/Max-Age) or short-lived;
            # a far-future expiry means it survives browser close and never times out, so anyone
            # reusing the browser (shared/public machine) stays logged in (the "old sessions" bug)
            import re as _re
            from datetime import datetime as _dt
            from email.utils import parsedate_to_datetime as _pdt
            life = None
            _m = _re.search(r"max-age=(\d+)", low)
            if _m:
                life = int(_m.group(1))
            else:
                _e = _re.search(r"expires=([^;]+)", sc, _re.I)
                if _e:
                    try:
                        _exp = _pdt(_e.group(1).strip())
                        if _exp.tzinfo is None:
                            _exp = _exp.replace(tzinfo=UTC)
                        life = (_exp - _dt.now(UTC)).total_seconds()
                    except Exception:
                        life = None
            if life is not None and life > 7 * 86400:      # persists > 7 days beyond the session
                _days = int(life // 86400)
                add(f"Session cookie never expires (persists ~{_days}d): {name}", "medium",
                    sc[:160],
                    f"The session cookie '{name}' has a lifetime of ~{_days} day(s) — it survives "
                    "the browser closing and never times out. Anyone who reuses the browser on a "
                    "shared or public machine stays authenticated without credentials. Issue "
                    "session-scoped cookies and enforce a server-side idle + absolute timeout.")

    # permissive CORS
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        add("Permissive CORS: wildcard origin with credentials", "high",
            "access-control-allow-origin: * ; access-control-allow-credentials: true",
            "ACAO '*' together with credentials lets any site read authenticated responses.")

    # version disclosure
    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        if h.get(hdr) and re.search(r"\d", h[hdr]):
            add(f"Version disclosure via {hdr}", "info", f"{hdr}: {h[hdr]}",
                "Software version in a response header aids targeted exploitation.")

    # directory listing
    if "index of /" in body.lower() and "<title>index of" in body.lower():
        add("Directory listing enabled", "medium", "'Index of /' autoindex page",
            "Server autoindex exposes files that are not meant to be browsable.")

    # insecure deserialization: serialized blobs served in cookies/body
    blob_src = " ".join(set_cookies) + " " + body[:4000]
    for mk in _SERIALIZED:
        if mk in blob_src:
            add("Serialized object exposed (possible insecure deserialization)", "medium",
                mk, "A serialized object is present in a cookie/response; if it is deserialized "
                "server-side without integrity checks it may enable gadget-chain attacks.")
            break

    # verbose errors / stack traces
    blow = body.lower()
    if any(m in blow for m in _STACK_MARKERS):
        marker = next(m for m in _STACK_MARKERS if m in blow)
        idx = blow.find(marker)
        add("Verbose error / stack trace disclosure", "medium", body[idx:idx + 160],
            "Response leaks a stack trace / framework error — reveals internals and paths.")

    return out


def cors_reflection(url: str, request_fn: RequestFn) -> PassiveFinding | None:
    """Active CORS probe: send an attacker Origin and see if it is reflected with
    credentials allowed (a reflected-origin + credentials = exploitable CORS)."""
    evil = "https://evil.example"
    try:
        r = request_fn("GET", url, headers={"Origin": evil}) or {}
    except Exception:
        return None
    h = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
    if h.get("access-control-allow-origin") == evil and h.get("access-control-allow-credentials", "").lower() == "true":
        return PassiveFinding(
            title="Reflected-origin CORS with credentials", severity="high",
            evidence=f"Origin: {evil} -> access-control-allow-origin: {evil}; credentials: true",
            detail="Server reflects an arbitrary Origin and allows credentials — any site can read "
                   "the victim's authenticated responses.", url=url)
    return None


def host_header_injection(url, request_fn):
    """Active probe: send a spoofed Host / X-Forwarded-Host and see if it is reflected
    into the response (links, redirects) — host-header injection / cache poisoning."""
    evil = "owl-hhi.example"
    try:
        r = request_fn("GET", url, headers={"Host": evil, "X-Forwarded-Host": evil}) or {}
    except Exception:
        return None
    hdrs = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
    if evil in hdrs.get("location", "") or evil in (r.get("body") or ""):
        return PassiveFinding(
            title="Host-header injection", severity="medium",
            evidence=f"Host: {evil} -> reflected in response (link/redirect)",
            detail="Server reflects an attacker-controlled Host/X-Forwarded-Host into links or "
                   "redirects — enables password-reset poisoning and web-cache poisoning.", url=url)
    return None


def passive_scan(assessment_id: str, target: str, inventory: list[dict],
                 request_fn: RequestFn, log: Callable[[str], None] = lambda m: None) -> int:
    """Fetch the target + a few pages, run passive checks + a CORS probe, and file each
    issue as a candidate finding. Returns how many were filed."""
    import secrets as _secrets

    from owlforge.store.db import session
    from owlforge.store.models import Finding

    urls = [target.rstrip("/")]
    for it in inventory:
        u = it.get("url", "")
        if u and u not in urls and it.get("source") in ("link", "content-discovery", "html", "form"):
            urls.append(u)
        if len(urls) >= 6:
            break

    seen: set[tuple] = set()
    results: list[PassiveFinding] = []
    for u in urls:
        try:
            r = request_fn("GET", u) or {}
        except Exception:
            continue
        if r.get("error"):
            continue
        results.extend(scan_response(u, r))
    cors = cors_reflection(target, request_fn)
    if cors:
        results.append(cors)
    hhi = host_header_injection(target, request_fn)
    if hhi:
        results.append(hhi)

    filed = 0
    with session() as s:
        for pf in results:
            key = (pf.title, pf.url)
            if key in seen:
                continue
            seen.add(key)
            s.add(Finding(
                id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
                title=pf.title, severity=pf.severity, endpoint=pf.url, method="GET",
                technical_analysis=pf.detail, proof_of_concept=pf.evidence, evidence=pf.evidence,
                impact="See description.",
                remediation="Set the appropriate security header / cookie flag / CORS policy.",
                status="candidate", confidence="high",
                validation_note="passive observation (deterministic)"))
            filed += 1
        if filed:
            s.commit()
    if filed:
        log(f"passive: {filed} configuration/observational finding(s)")
    return filed
