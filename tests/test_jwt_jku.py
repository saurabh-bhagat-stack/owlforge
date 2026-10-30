"""jku header injection: owlforge hosts a JWKS (via an OAST tunnel) and points the token's jku at
it. The mock 'fetches' the hosted JWKS and verifies against it (end-to-end forging + wiring); a
server that ignores jku yields nothing."""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from owlforge.engine.jwtattack import _b64e, _jwk_to_pem, jwt_attack_scan


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


class _JkuLab:
    """RS256 app. `trust_jku`=True fetches and trusts the key at the token's jku URL (vulnerable)."""
    OK = "<h1>account</h1>"

    def __init__(self, trust_jku):
        self.trust_jku = trust_jku
        self.served = None
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub = self.key.public_key()
        h = {"typ": "JWT", "alg": "RS256", "kid": "server-1"}
        si = (_b64e(json.dumps(h, separators=(",", ":")).encode()) + "." +
              _b64e(json.dumps({"sub": "wiener"}, separators=(",", ":")).encode()))
        self.token = si + "." + _b64e(self.key.sign(si.encode(), padding.PKCS1v15(),
                                                     hashes.SHA256()))

    # OAST tunnel the jku attack uses to host its JWKS
    def oast_start(self, provider="interactsh", *, server="", token="", ngrok_token="",
                   serve_path="", serve_body=""):
        try:
            self.served = json.loads(serve_body) if serve_body else None
        except Exception:
            self.served = None
        return {"mode": "tunnel", "domain": "owl-abc.trycloudflare.com",
                "hits_file": "/tmp/h"}

    def oast_stop(self):
        return {"ok": True}

    def _verify(self, tok):
        try:
            hseg, pseg, sseg = tok.split(".", 2)
            header = json.loads(_b64d(hseg))
            si = (hseg + "." + pseg).encode()
            sig = _b64d(sseg)
        except Exception:
            return False
        if (header.get("alg") or "").upper() != "RS256":
            return False
        if "jku" in header:
            if not (self.trust_jku and self.served):
                return False
            try:
                pk = serialization.load_pem_public_key(_jwk_to_pem(self.served["keys"][0]))
                pk.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
                return True
            except Exception:
                return False
        if "jwk" in header or "x5c" in header:
            return False                       # this lab trusts neither embedded key form
        try:
            self.pub.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
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
        return ({"status": 200, "headers": {}, "body": self.OK} if tok and self._verify(tok)
                else {"status": 401, "headers": {}, "body": "unauthorized"})


def _run(trust, tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    lab = _JkuLab(trust)
    jwt_attack_scan("a1", [{"url": "http://app/me", "method": "GET"}], lab,
                    session_headers={"Authorization": f"Bearer {lab.token}"},
                    log=lambda m: None, target="http://app")
    return _findings(db)


def test_jku_injection_detected(tmp_path, monkeypatch):
    found = _run(True, tmp_path, monkeypatch)
    assert any("jku header injection" in f.title for f in found), [f.title for f in found]
    assert all(f.status == "validated" for f in found)


def test_server_ignoring_jku_yields_nothing(tmp_path, monkeypatch):
    found = _run(False, tmp_path, monkeypatch)
    assert found == [], [f.title for f in found]
