"""JWT forgery suite: alg:none (token-less), weak HMAC secret; no false positives when secure."""
from __future__ import annotations

import hashlib
import hmac

from owlforge.engine.jwtattack import (
    _b64e,
    _bearer,
    _decode,
    _hs,
    jwt_attack_scan,
)

_REAL = b"realsecret_not_in_wordlist_zzz"


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


def _verify_hs(tok, secret) -> bool:
    si, _, sig = tok.rpartition(".")
    return _b64e(hmac.new(secret, si.encode(), hashlib.sha256).digest()) == sig


class _AlgNoneApp:
    """/api/me rejects a bad signature (401) but trusts an alg:none token (200) — vulnerable."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if not url.endswith("/api/me"):
            return {"status": 404, "body": "nf"}
        tok = _bearer(headers)
        if not tok:
            return {"status": 401, "body": "no token"}
        h, p, _s = _decode(tok)
        if (h or {}).get("alg") == "none":
            user = (p or {}).get("user", "")
            return {"status": 200, "body": f'{{"user":"{user}"}}'}
        return {"status": 200, "body": "{}"} if _verify_hs(tok, _REAL) else {"status": 401, "body": "bad"}


class _WeakSecretApp:
    """/api/me rejects alg:none AND bad sigs, but the HMAC secret is a wordlist word ('secret')."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if not url.endswith("/api/me"):
            return {"status": 404, "body": "nf"}
        tok = _bearer(headers)
        if not tok:
            return {"status": 401, "body": "no"}
        h, _p, _s = _decode(tok)
        if (h or {}).get("alg", "").lower() == "none":
            return {"status": 401, "body": "nope"}
        return {"status": 200, "body": "{}"} if _verify_hs(tok, b"secret") else {"status": 401, "body": "bad"}


class _SecureApp:
    """Rejects everything except a correctly-signed token — must yield no findings."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if not url.endswith("/api/me"):
            return {"status": 404, "body": "nf"}
        tok = _bearer(headers)
        h, _p, _s = _decode(tok or "")
        if not tok or (h or {}).get("alg", "").lower() == "none":
            return {"status": 401, "body": "no"}
        return {"status": 200, "body": "{}"} if _verify_hs(tok, _REAL) else {"status": 401, "body": "bad"}


def test_alg_none_bypass_confirmed_without_session_token(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = jwt_attack_scan("a", [], _AlgNoneApp(), {}, target="https://t/")   # no session JWT at all
    assert n == 1
    f = _findings(db)
    assert len(f) == 1 and f[0].severity == "critical" and "alg:none" in f[0].title


def test_weak_hmac_secret_cracked_and_forged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    sess = {"Authorization": "Bearer " + _hs({"typ": "JWT", "alg": "HS256"},
            {"user": "bob", "role": "user"}, b"secret", "sha256")}
    n = jwt_attack_scan("a", [], _WeakSecretApp(), sess, target="https://t/")
    assert n == 1
    assert "weak HMAC secret" in _findings(db)[0].title


def test_secure_app_yields_no_findings(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    sess = {"Authorization": "Bearer " + _hs({"typ": "JWT", "alg": "HS256"},
            {"user": "bob"}, _REAL, "sha256")}
    assert jwt_attack_scan("a", [], _SecureApp(), sess, target="https://t/") == 0
    assert _findings(db) == []
