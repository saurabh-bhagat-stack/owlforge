"""'Unverified signature' JWT class (PortSwigger): a server that does not verify the signature at
all. The reject-bad-sig oracle the other forgeries rely on is impossible here, so detection uses
an anon-denied vs invalid-signature-accepted differential, plus an admin-identity escalation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

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


def _mk(payload, secret):
    h = {"alg": "HS256", "typ": "JWT"}
    si = (_b64e(json.dumps(h, separators=(",", ":")).encode()) + "." +
          _b64e(json.dumps(payload, separators=(",", ":")).encode()))
    sig = _b64e(hmac.new(secret, si.encode(), hashlib.sha256).digest())
    return si + "." + sig


_LOGIN = ('<html><body><form action="/login" method=POST><input name="username">'
          '<input type="password" name="password">Log in</form></body></html>')


class _JwtLab:
    """GET /my-account is token-gated; GET /admin needs sub==administrator. `verify` toggles
    whether the signature is actually checked (False = the vulnerable lab)."""
    def __init__(self, verify: bool):
        self.verify = verify
        self.secret = b"s3cr3t-key-not-in-wordlist"
        self.wiener = _mk({"sub": "wiener", "name": "wiener"}, self.secret)

    def _tok(self, headers):
        import re
        for k, v in (headers or {}).items():
            if k.lower() == "authorization" and isinstance(v, str) and "." in v:
                return v.split()[-1]
            if k.lower() == "cookie" and isinstance(v, str):
                m = re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", v)
                if m:
                    return m.group(0)
        return None

    def _payload(self, tok):
        if not tok:
            return None
        try:
            hseg, pseg, sseg = tok.split(".", 2)
            pay = json.loads(base64.urlsafe_b64decode(pseg + "=" * (-len(pseg) % 4)))
        except Exception:
            return None
        if not self.verify:
            return pay                                  # vulnerable: signature ignored
        good = _b64e(hmac.new(self.secret, (hseg + "." + pseg).encode(), hashlib.sha256).digest())
        return pay if hmac.compare_digest(good, sseg) else None

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=False, timeout_ms=30000):
        from urllib.parse import urlsplit
        path = urlsplit(url).path.rstrip("/") or "/"
        pay = self._payload(self._tok(headers))
        if path == "/my-account":
            if pay:
                return {"status": 200, "headers": {},
                        "body": f"<h1>My account</h1><p>Username: {pay.get('sub')}</p>"
                                "<a href=/logout>Log out</a>"}
            return {"status": 200, "headers": {}, "body": _LOGIN}       # anon -> login page
        if path == "/admin":
            if pay and pay.get("sub") == "administrator":
                return {"status": 200, "headers": {},
                        "body": "<h1>Admin panel</h1><p>Delete any user here</p>"}
            if pay:
                return {"status": 401, "headers": {},
                        "body": "Admin interface only available to administrators"}
            return {"status": 200, "headers": {}, "body": _LOGIN}
        return {"status": 404, "headers": {}, "body": "not found"}


def _run(lab, tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    headers = {"Cookie": f"session={lab.wiener}"}
    jwt_attack_scan("a1", [], lab, session_headers=headers, log=lambda m: None,
                    target="http://app")
    return _findings(db)


def test_unverified_signature_detected(tmp_path, monkeypatch):
    found = _run(_JwtLab(verify=False), tmp_path, monkeypatch)
    titles = [f.title for f in found]
    assert any("signature not verified" in t for t in titles), titles
    assert all(f.status == "validated" and f.severity == "critical" for f in found)


def test_unverified_signature_privilege_escalation(tmp_path, monkeypatch):
    found = _run(_JwtLab(verify=False), tmp_path, monkeypatch)
    titles = [f.title for f in found]
    assert any("privilege escalation to 'administrator'" in t for t in titles), titles


def test_signature_verifying_server_yields_nothing(tmp_path, monkeypatch):
    found = _run(_JwtLab(verify=True), tmp_path, monkeypatch)
    assert found == [], [f.title for f in found]
