"""RS-family JWT forgeries (needs `cryptography`): RS256->HS256 confusion, and jwk/x5c self-signed
key injection. Each is gated by the live oracle, so a non-vulnerable server yields nothing."""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from owlforge.engine.jwtattack import _b64e, _pub_jwk, jwt_attack_scan


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _findings(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return list(s.exec(select(Finding)))


def _b64d(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


class _JwtServer:
    """A JWT-guarded app. GET /me is the oracle. It issues a real RS256 token and verifies
    presented tokens under `policy`: 'safe' (only the server key), 'jwk', 'x5c', or 'confusion'
    (verifies HS256 tokens using the server's PUBLIC-key PEM as the HMAC secret — the classic bug).
    """
    OK = "ACCOUNT PAGE: welcome back"

    def __init__(self, policy):
        self.policy = policy
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub = self.key.public_key()
        self.pem = self.pub.public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
        self.token = self._issue({"user": "bob", "role": "user", "sub": "42"})

    def _issue(self, payload):
        h = {"typ": "JWT", "alg": "RS256", "kid": "server-1"}
        si = (_b64e(json.dumps(h, separators=(",", ":")).encode()) + "." +
              _b64e(json.dumps(payload, separators=(",", ":")).encode()))
        sig = self.key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
        return si + "." + _b64e(sig)

    def _verify(self, token):
        try:
            hseg, pseg, sseg = token.split(".", 2)
            header = json.loads(_b64d(hseg))
            si = (hseg + "." + pseg).encode()
            sig = _b64d(sseg)
        except Exception:
            return False
        alg = (header.get("alg") or "").upper()
        # legitimate path: RS256 against the server's own key
        if alg == "RS256" and "jwk" not in header and "x5c" not in header:
            try:
                self.pub.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
                return True
            except Exception:
                return False
        if self.policy == "jwk" and alg == "RS256" and header.get("jwk"):
            try:
                from owlforge.engine.jwtattack import _jwk_to_pem
                pk = serialization.load_pem_public_key(_jwk_to_pem(header["jwk"]))
                pk.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
                return True
            except Exception:
                return False
        if self.policy == "x5c" and alg == "RS256" and header.get("x5c"):
            try:
                from cryptography import x509
                der = base64.b64decode(header["x5c"][0])
                pk = x509.load_der_x509_certificate(der).public_key()
                pk.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
                return True
            except Exception:
                return False
        if self.policy == "confusion" and alg == "HS256":
            import hashlib
            import hmac
            good = _b64e(hmac.new(self.pem, si, hashlib.sha256).digest())
            return hmac.compare_digest(good, sseg)
        return False

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=False, timeout_ms=30000):
        path = url.split("://", 1)[-1].split("/", 1)
        path = "/" + (path[1] if len(path) > 1 else "")
        if self.policy == "confusion" and path in ("/jwks.json", "/.well-known/jwks.json"):
            jwk = _pub_jwk(self.key)
            return {"status": 200, "headers": {}, "body": json.dumps({"keys": [jwk]})}
        if path.rstrip("/") == "/me":
            tok = ""
            for k, v in (headers or {}).items():
                if k.lower() == "authorization":
                    tok = v.split(None, 1)[-1]
            if tok and self._verify(tok):
                return {"status": 200, "headers": {}, "body": self.OK}
            return {"status": 401, "headers": {}, "body": "unauthorized"}
        return {"status": 404, "headers": {}, "body": "nope"}


def _run(server, tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    inv = [{"url": "http://app/me", "method": "GET"}]
    hdr = {"Authorization": f"Bearer {server.token}"}
    jwt_attack_scan("a1", inv, server, session_headers=hdr, log=lambda m: None,
                    target="http://app")
    return _findings(db)


def test_jwk_injection_detected(tmp_path, monkeypatch):
    found = _run(_JwtServer("jwk"), tmp_path, monkeypatch)
    kinds = [f.title for f in found]
    assert any("jwk header injection" in k for k in kinds), kinds
    assert all(f.status == "validated" and f.severity == "critical" for f in found)


def test_x5c_injection_detected(tmp_path, monkeypatch):
    found = _run(_JwtServer("x5c"), tmp_path, monkeypatch)
    assert any("x5c header injection" in f.title for f in found), [f.title for f in found]


def test_rs_to_hs_confusion_detected(tmp_path, monkeypatch):
    found = _run(_JwtServer("confusion"), tmp_path, monkeypatch)
    assert any("algorithm confusion" in f.title for f in found), [f.title for f in found]


def test_safe_server_yields_nothing(tmp_path, monkeypatch):
    found = _run(_JwtServer("safe"), tmp_path, monkeypatch)
    assert found == [], [f.title for f in found]
