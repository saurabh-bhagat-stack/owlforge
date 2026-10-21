"""Client-side prototype pollution (browser-verified)."""
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
    """vuln=True => the page pollutes Object.prototype for the __proto__ payload."""
    def __init__(self, vuln=True):
        self.vuln = vuln
        self.calls = []

    def proto_check(self, url, probe, *, headers=None, timeout_ms=15000):
        self.calls.append(url)
        polluted = self.vuln and "__proto__[" in url
        return {"polluted": polluted, "value": "owlPOLLUTED" if polluted else None}


INV = [{"url": "https://t/app", "method": "GET", "params": []},
       {"url": "https://t/app?x=1", "method": "GET", "params": ["x"]}]  # same path -> deduped


def test_confirms_prototype_pollution(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.protopoll import proto_pollution_scan
    from owlforge.store.models import Finding
    n = proto_pollution_scan("a1", INV, _SB(vuln=True), {})
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "prototype pollution" in f.title.lower()
    assert f.status == "validated" and f.severity == "high"


def test_clean_page_no_finding(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.protopoll import proto_pollution_scan
    from owlforge.store.models import Finding
    assert proto_pollution_scan("a2", INV, _SB(vuln=False), {}) == 0
    with db.session() as s:
        assert s.exec(select(Finding).where(Finding.assessment_id == "a2")).all() == []


def test_noop_without_sandbox(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.protopoll import proto_pollution_scan
    assert proto_pollution_scan("a3", INV, None, {}) == 0
