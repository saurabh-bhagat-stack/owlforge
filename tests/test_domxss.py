"""Browser-driven DOM/JS XSS."""

from __future__ import annotations


def test_browser_xss_scan_files_validated_on_execution(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    from sqlmodel import select

    from owlforge.engine.domxss import browser_xss_scan
    from owlforge.store.models import Finding

    class _SB:
        """Executes only when the payload rides the URL fragment (a DOM sink)."""
        def xss_check(self, url, token, *, headers=None, timeout_ms=15_000):
            executed = "#" in url and token in url
            return {"executed": executed, "via": "fragment", "status": 200}

    n = browser_xss_scan("asmt_dx", [{"url": "https://t/page", "param": "msg"}], _SB(), cap=8)
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "asmt_dx")).one()
    assert f.status == "validated" and "DOM-based" in f.title


def test_browser_xss_scan_noop_without_xss_check():
    from owlforge.engine.domxss import browser_xss_scan
    assert browser_xss_scan("a", [{"url": "https://t", "param": "q"}], object()) == 0
