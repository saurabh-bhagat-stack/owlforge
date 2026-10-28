"""Boolean-based blind SQLi: TRUE matches baseline, FALSE differs (double-confirmed)."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _Bool:
    """Injectable: a TRUE condition returns the full row (like the valid baseline), a FALSE
    one returns a short 'no rows' page."""
    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "") if params else (body or "")
        truthy = v == "1" or "'1'='1" in v or "1=1" in v
        return {"status": 200, "body": "ITEM-DETAIL " * 40 if truthy else "no results"}


class _Static:
    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        return {"status": 200, "body": "always the same page " * 40}


INV = [{"url": "https://t/item", "method": "GET", "params": ["id"]}]


def test_confirms_boolean_based_sqli(tmp_path, monkeypatch):
    from sqlmodel import select

    from owlforge.engine.blindsqli import boolean_based_sqli_scan
    from owlforge.store.models import Finding
    db = _db(tmp_path, monkeypatch)
    assert boolean_based_sqli_scan("a", INV, _Bool(), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a")).one()
    assert "boolean-based" in f.title.lower() and f.status == "validated"
    assert f.repro_url and f.repro_params.get("id") == "1"   # sqliextract can pick this up


def test_static_page_not_flagged(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.blindsqli import boolean_based_sqli_scan
    assert boolean_based_sqli_scan("b", INV, _Static(), {}) == 0
