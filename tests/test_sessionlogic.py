"""Logout session-invalidation check."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    """authed session accesses /my-account; anon denied. After /logout, session is either
    still valid (vuln) or invalidated (ok) depending on `invalidates`."""
    def __init__(self, invalidates=False):
        self.invalidates = invalidates
        self.logged_out = False
    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        authed = "u=A" in (headers or {}).get("Cookie", "")
        if "/logout" in url:
            self.logged_out = True
            return {"status": 302, "body": "redirecting to login " * 4}
        if "/my-account" in url:
            if not authed:
                return {"status": 302, "body": "please log in " * 4}       # anon denied
            if self.logged_out and self.invalidates:
                return {"status": 302, "body": "please log in " * 4}       # session killed
            return {"status": 200, "body": "ACCOUNT PANEL alice email orders " * 6}
        return {"status": 404, "body": ""}


INV = [
    {"url": "https://t/my-account", "method": "GET", "params": []},
    {"url": "https://t/logout", "method": "GET", "params": []},
]
SESS = {"Cookie": "u=A"}


def test_flags_when_session_survives_logout(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.sessionlogic import session_scan
    from owlforge.store.models import Finding
    assert session_scan("a1", INV, _SB(invalidates=False), SESS) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "not invalidated" in f.title.lower() and f.status == "candidate"


def test_no_flag_when_session_invalidated(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.sessionlogic import session_scan
    assert session_scan("a2", INV, _SB(invalidates=True), SESS) == 0


def test_noop_without_session(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.sessionlogic import session_scan
    assert session_scan("a3", INV, _SB(), {}) == 0
