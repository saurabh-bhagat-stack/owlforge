"""Auth-logic: JWT alg=none bypass + weak-secret cracking."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(secret: str):
    h = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64(json.dumps({"user": "carlos", "role": "user"}).encode())
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


WEAK = _jwt("secret")                 # crackable from the wordlist
STRONG = _jwt(os.urandom(32).hex())   # not crackable


class _SB:
    """Fake sandbox for the alg=none differential. `alg_none` = server accepts none-token;
    `gated` = endpoint is actually token-protected."""

    def __init__(self, real, alg_none=True, gated=True):
        self.real = real
        self.alg_none = alg_none
        self.gated = gated

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        ck = (headers or {}).get("Cookie", "")
        tok = ck.split("session=", 1)[1] if "session=" in ck else ""
        ok = {"status": 200, "body": "ACCOUNT PANEL EMAIL ORDERS " * 8}
        deny = {"status": 401, "body": "unauthorized"}
        if not self.gated:
            return ok
        if "zzz" in tok:
            return deny
        if tok.endswith("."):            # forged alg=none token
            return ok if self.alg_none else deny
        if tok == self.real:
            return ok
        return deny


INV = [{"url": "https://t/my-account", "method": "GET", "params": []}]


def test_weak_secret_cracked(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.authlogic import jwt_scan
    from owlforge.store.models import Finding
    # no inventory -> no endpoint -> only the (endpoint-free) weak-secret check runs
    n = jwt_scan("a1", [], _SB(WEAK), {"Cookie": f"session={WEAK}"})
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "weak" in f.title.lower() and f.severity == "critical" and f.status == "validated"


def test_alg_none_accepted(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.authlogic import jwt_scan
    from owlforge.store.models import Finding
    n = jwt_scan("a2", INV, _SB(STRONG, alg_none=True, gated=True), {"Cookie": f"session={STRONG}"})
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a2")).all()
    assert n == 1 and any("alg=none" in f.title for f in rows)
    assert all(f.status == "validated" and f.severity == "critical" for f in rows)


def test_alg_none_rejected_no_finding(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.authlogic import jwt_scan
    assert jwt_scan("a3", INV, _SB(STRONG, alg_none=False, gated=True),
                    {"Cookie": f"session={STRONG}"}) == 0


def test_not_token_gated_no_conclusion(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.authlogic import jwt_scan
    # endpoint returns 200 to everyone incl. garbage token -> can't conclude -> no finding
    assert jwt_scan("a4", INV, _SB(STRONG, alg_none=True, gated=False),
                    {"Cookie": f"session={STRONG}"}) == 0


def test_no_jwt_noop(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.authlogic import jwt_scan
    assert jwt_scan("a5", INV, _SB(STRONG), {"Cookie": "session=plain-not-a-jwt"}) == 0
    assert jwt_scan("a6", INV, _SB(STRONG), {}) == 0
