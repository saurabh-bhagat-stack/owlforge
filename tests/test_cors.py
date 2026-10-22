"""Deterministic CORS misconfiguration probe."""
from __future__ import annotations

EVIL = "https://owlforge-cors-probe.example"


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    def __init__(self, resp_headers):
        self._h = resp_headers

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        # reflect the Origin only if configured to
        h = dict(self._h)
        if h.get("access-control-allow-origin") == "REFLECT":
            h["access-control-allow-origin"] = (headers or {}).get("Origin", "")
        return {"status": 200, "headers": h, "body": "ok"}


_INV = [{"url": "https://t/api/data", "method": "GET", "params": [], "source": "link"}]


def _titles(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a")).all()]


def test_reflected_origin_with_credentials_is_high(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.corsscan import cors_scan
    sb = _SB({"access-control-allow-origin": "REFLECT", "access-control-allow-credentials": "true"})
    assert cors_scan("a", _INV, sb, {}) == 1
    assert any("credentialed" in t for t in _titles(db))


def test_reflected_origin_no_credentials_is_medium(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.corsscan import cors_scan
    sb = _SB({"access-control-allow-origin": "REFLECT"})
    assert cors_scan("a", _INV, sb, {}) == 1
    assert any("arbitrary origin" in t for t in _titles(db))


def test_null_origin_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.corsscan import cors_scan
    assert cors_scan("a", _INV, _SB({"access-control-allow-origin": "null"}), {}) == 1
    assert any("null origin" in t for t in _titles(db))


def test_wildcard_is_not_flagged(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.corsscan import cors_scan
    assert cors_scan("a", _INV, _SB({"access-control-allow-origin": "*"}), {}) == 0


def test_no_cors_headers_not_flagged(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.corsscan import cors_scan
    assert cors_scan("a", _INV, _SB({}), {}) == 0


def test_no_sandbox():
    from owlforge.engine.corsscan import cors_scan
    assert cors_scan("a", _INV, None, {}) == 0
