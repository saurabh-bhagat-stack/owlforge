"""Time-based blind SQLi (double-confirmed)."""
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
    """Returns elapsed_ms ~5000 when a SLEEP/WAITFOR/pg_sleep payload is injected (vuln),
    else ~120ms. jitter=True makes the FIRST injected call slow but the confirm fast."""
    def __init__(self, vuln=True, jitter=False):
        self.vuln = vuln
        self.jitter = jitter
        self._first = True

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        blob = f"{params} {body}"
        inj = any(k in blob for k in ("SLEEP(", "WAITFOR", "pg_sleep"))
        if inj and self.jitter:
            slow = self._first
            self._first = False
            return {"status": 200, "body": "x" * 60, "elapsed_ms": 5200 if slow else 110}
        if inj and self.vuln:
            return {"status": 200, "body": "x" * 60, "elapsed_ms": 5200}
        return {"status": 200, "body": "x" * 60, "elapsed_ms": 115}


INV = [{"url": "https://t/item", "method": "GET", "params": ["id"]}]


def test_confirms_time_based_blind_sqli(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.blindsqli import time_based_sqli_scan
    from owlforge.store.models import Finding
    assert time_based_sqli_scan("a1", INV, _SB(vuln=True), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "time-based" in f.title.lower() and f.status == "validated"


def test_not_vulnerable_no_finding(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.blindsqli import time_based_sqli_scan
    assert time_based_sqli_scan("a2", INV, _SB(vuln=False), {}) == 0


def test_jitter_single_spike_not_flagged(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.blindsqli import time_based_sqli_scan
    # one slow response (jitter) but the confirm is fast -> must NOT flag
    assert time_based_sqli_scan("a3", INV, _SB(jitter=True), {}) == 0


def test_noop_without_sandbox(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.blindsqli import time_based_sqli_scan
    assert time_based_sqli_scan("a4", INV, None, {}) == 0
