"""Object-ID-harvesting BOLA: identity A requests an object whose opaque ID belongs to identity B.
Needs >=2 identities; read-only; a server that checks object ownership yields nothing."""
from __future__ import annotations

import json

from owlforge.engine.bola import bola_scan


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


UUID_A = "11111111-1111-1111-1111-111111111111"
UUID_B = "22222222-2222-2222-2222-222222222222"
VEH = f"http://app/api/v2/vehicle/{UUID_A}/location"       # alice's own (seeds the template)
DASH = "http://app/api/v2/user/dashboard"


class _BolaApp:
    """`enforce`=False is vulnerable (any authed user reads any vehicle by id); True checks owner."""
    def __init__(self, enforce):
        self.enforce = enforce
        self.owner = {UUID_A: "A", UUID_B: "B"}   # token -> owns which vehicle

    def _user(self, headers):
        for k, v in (headers or {}).items():
            if k.lower() == "authorization":
                return v.split()[-1]
        return None

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=False, timeout_ms=30000):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        who = self._user(headers)
        if path.rstrip("/") == "/api/v2/user/dashboard":
            if not who:
                return {"status": 401, "headers": {}, "body": "unauthorized"}
            veh = UUID_A if who == "A" else UUID_B
            return {"status": 200, "headers": {},
                    "body": json.dumps({"name": f"user-{who}", "vehicleId": veh})}
        if path.startswith("/api/v2/vehicle/") and path.endswith("/location"):
            vid = path.split("/")[4]
            if not who:
                return {"status": 401, "headers": {}, "body": "unauthorized"}
            if self.enforce and self.owner.get(vid) != who:
                return {"status": 403, "headers": {}, "body": "forbidden"}
            return {"status": 200, "headers": {},
                    "body": json.dumps({"vehicleId": vid, "location": "12.9,77.5"})}
        return {"status": 404, "headers": {}, "body": "nope"}


def _run(enforce, tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    inv = [{"url": DASH, "method": "GET"}, {"url": VEH, "method": "GET"}]
    idents = [{"label": "alice", "role": "user", "headers": {"Authorization": "Bearer A"}},
              {"label": "bob", "role": "user", "headers": {"Authorization": "Bearer B"}}]
    bola_scan("a1", inv, _BolaApp(enforce), idents, log=lambda m: None, target="http://app")
    return _findings(db)


def test_bola_detected_cross_identity(tmp_path, monkeypatch):
    found = _run(False, tmp_path, monkeypatch)
    assert len(found) >= 1, found
    f = found[0]
    assert "object-level authorization" in f.title.lower()
    assert f.status == "validated" and f.severity == "high"
    assert UUID_B in f.endpoint        # alice read bob's vehicle id


def test_ownership_enforced_yields_nothing(tmp_path, monkeypatch):
    assert _run(True, tmp_path, monkeypatch) == []


def test_single_identity_is_skipped(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    inv = [{"url": DASH, "method": "GET"}, {"url": VEH, "method": "GET"}]
    idents = [{"label": "alice", "role": "user", "headers": {"Authorization": "Bearer A"}}]
    bola_scan("a1", inv, _BolaApp(False), idents, log=lambda m: None, target="http://app")
    assert _findings(db) == []
