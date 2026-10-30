"""kid-header forgeries (path traversal -> empty key, SQL injection -> attacker key) and the
weak-signing-key brute against the expanded wordlist. All oracle-gated: a server that verifies
properly yields nothing."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from owlforge.engine.jwtattack import _b64e, jwt_attack_scan


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


def _b64d(x):
    x = x.encode() if isinstance(x, str) else x
    return base64.urlsafe_b64decode(x + b"=" * (-len(x) % 4))


def _sign_hs(payload, secret, kid=None):
    h = {"typ": "JWT", "alg": "HS256"}
    if kid is not None:
        h["kid"] = kid
    si = (_b64e(json.dumps(h, separators=(",", ":")).encode()) + "." +
          _b64e(json.dumps(payload, separators=(",", ":")).encode()))
    return si + "." + _b64e(hmac.new(secret, si.encode(), hashlib.sha256).digest())


class _KidLab:
    """RS256 app whose key lookup is vulnerable per `mode`: 'traversal' loads an empty key when
    kid points at /dev/null; 'sqli' returns a key we inject; 'safe' pins RS256 and ignores kid."""
    OK = "<h1>My account</h1>"

    def __init__(self, mode):
        self.mode = mode
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub = self.key.public_key()
        h = {"typ": "JWT", "alg": "RS256", "kid": "server-key"}
        si = (_b64e(json.dumps(h, separators=(",", ":")).encode()) + "." +
              _b64e(json.dumps({"sub": "wiener", "role": "user"}, separators=(",", ":")).encode()))
        self.token = si + "." + _b64e(self.key.sign(si.encode(), padding.PKCS1v15(),
                                                     hashes.SHA256()))

    def _verify(self, tok):
        try:
            hseg, pseg, sseg = tok.split(".", 2)
            header = json.loads(_b64d(hseg))
            si = (hseg + "." + pseg).encode()
            sig = _b64d(sseg)
        except Exception:
            return False
        alg = (header.get("alg") or "").upper()
        kid = header.get("kid") or ""
        if alg == "RS256" and "dev/null" not in kid and "UNION" not in kid.upper():
            try:
                self.pub.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
                return True
            except Exception:
                return False
        if self.mode == "traversal" and alg == "HS256" and "dev/null" in kid:
            return hmac.compare_digest(_b64e(hmac.new(b"", si, hashlib.sha256).digest()), sseg)
        if self.mode == "sqli" and alg == "HS256" and "UNION SELECT" in kid.upper():
            # naive server uses the RETURNED string (the base64 literal) verbatim as the key
            m = kid.split("'")
            returned = next((p for p in m if p and "UNION" not in p.upper() and "-" not in p
                             and "#" not in p), "")
            return hmac.compare_digest(
                _b64e(hmac.new(returned.encode(), si, hashlib.sha256).digest()), sseg)
        return False

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=False, timeout_ms=30000):
        from urllib.parse import urlsplit
        if urlsplit(url).path.rstrip("/") != "/me":
            return {"status": 404, "headers": {}, "body": "nope"}
        tok = ""
        for k, v in (headers or {}).items():
            if k.lower() == "authorization":
                tok = v.split()[-1]
        if tok and self._verify(tok):
            return {"status": 200, "headers": {}, "body": self.OK}
        return {"status": 401, "headers": {}, "body": "unauthorized"}


class _WeakKeyLab:
    """HS256 app whose secret is a common one now in the expanded wordlist."""
    OK = "<h1>My account</h1>"
    SECRET = b"secret1"

    def __init__(self):
        self.token = _sign_hs({"sub": "wiener", "role": "user"}, self.SECRET)

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=False, timeout_ms=30000):
        from urllib.parse import urlsplit
        if urlsplit(url).path.rstrip("/") != "/me":
            return {"status": 404, "headers": {}, "body": "nope"}
        tok = ""
        for k, v in (headers or {}).items():
            if k.lower() == "authorization":
                tok = v.split()[-1]
        try:
            hseg, pseg, sseg = tok.split(".", 2)
            good = _b64e(hmac.new(self.SECRET, f"{hseg}.{pseg}".encode(), hashlib.sha256).digest())
            ok = hmac.compare_digest(good, sseg)
        except Exception:
            ok = False
        return ({"status": 200, "headers": {}, "body": self.OK} if ok
                else {"status": 401, "headers": {}, "body": "unauthorized"})


def _run(lab, tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    hdr = {"Authorization": f"Bearer {lab.token}"}
    jwt_attack_scan("a1", [{"url": "http://app/me", "method": "GET"}], lab,
                    session_headers=hdr, log=lambda m: None, target="http://app")
    return _findings(db)


def test_kid_path_traversal_detected(tmp_path, monkeypatch):
    found = _run(_KidLab("traversal"), tmp_path, monkeypatch)
    assert any("kid header path traversal" in f.title for f in found), [f.title for f in found]


def test_kid_sql_injection_detected(tmp_path, monkeypatch):
    found = _run(_KidLab("sqli"), tmp_path, monkeypatch)
    assert any("kid header SQL injection" in f.title for f in found), [f.title for f in found]


def test_weak_signing_key_cracked_from_expanded_wordlist(tmp_path, monkeypatch):
    found = _run(_WeakKeyLab(), tmp_path, monkeypatch)
    assert any("weak HMAC secret" in f.title for f in found), [f.title for f in found]


def test_safe_kid_server_yields_nothing(tmp_path, monkeypatch):
    found = _run(_KidLab("safe"), tmp_path, monkeypatch)
    assert found == [], [f.title for f in found]
