"""Request-smuggling time-based detection."""

from __future__ import annotations


def _iso(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def test_smuggle_scan_files_on_potential(tmp_path, monkeypatch):
    db = _iso(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.smuggle import smuggle_scan
    from owlforge.store.models import Finding

    class _SB:
        def smuggle_probe(self, url, *, timeout_s=10.0):
            return {"potential": True, "kind": "CL.TE", "baseline_s": 0.3, "clte_s": 9.5, "tecl_s": 0.3}

    assert smuggle_scan("asmt_sm", "https://t/", _SB()) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "asmt_sm")).one()
    assert "request smuggling" in f.title.lower() and f.confidence == "low"


def test_smuggle_scan_quiet_when_no_desync(tmp_path, monkeypatch):
    _iso(tmp_path, monkeypatch)
    from owlforge.engine.smuggle import smuggle_scan

    class _SB:
        def smuggle_probe(self, url, *, timeout_s=10.0):
            return {"potential": False, "baseline_s": 0.3, "clte_s": 0.3, "tecl_s": 0.3}

    assert smuggle_scan("asmt_sm2", "https://t/", _SB()) == 0
