"""Password-reset host-header poisoning (candidate)."""
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
    def __init__(self, reflect=False, accept=True):
        self.reflect = reflect
        self.accept = accept

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30_000):
        if self.reflect:
            return {"status": 200, "headers": {}, "body": "reset link: http://owl-pwreset.example/r/abc"}
        if self.accept:
            return {"status": 200, "headers": {}, "body": "If that email exists we sent a link"}
        return {"status": 404, "headers": {}, "body": "not found"}


INV = [{"url": "https://t/forgot-password", "method": "POST", "params": ["email"]}]


def test_reflected_host_high_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.pwreset import password_reset_scan
    from owlforge.store.models import Finding
    assert password_reset_scan("a1", INV, _SB(reflect=True), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "password-reset" in f.title.lower() and f.status == "candidate" and f.severity == "high"


def test_accepted_medium_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.pwreset import password_reset_scan
    from owlforge.store.models import Finding
    assert password_reset_scan("a2", INV, _SB(reflect=False, accept=True), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a2")).one()
    assert f.severity == "medium" and f.status == "candidate"


def test_no_reset_endpoint_noop(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.pwreset import password_reset_scan
    assert password_reset_scan("a3", [{"url": "https://t/about", "params": []}], _SB(), {}) == 0
