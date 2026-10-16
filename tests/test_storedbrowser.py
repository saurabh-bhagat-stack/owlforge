"""Browser-driven stored XSS (formless/SPA submit + observe)."""

from __future__ import annotations


def test_browser_stored_scan_files_on_execution(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    from sqlmodel import select

    from owlforge.engine.storedbrowser import browser_stored_scan
    from owlforge.store.models import Finding

    class _SB:
        def interact(self, url, token, *, headers=None, check_url=None, timeout_ms=20_000):
            # the /blog page stores+executes; others don't
            executed = url.endswith("/blog")
            return {"submitted": True, "filled": 2, "executed": executed, "via": "script-exec"}

    inv = [
        {"url": "https://t/blog", "method": "GET", "params": [], "source": "form"},
        {"url": "https://t/about", "method": "GET", "params": [], "source": "link"},
    ]
    n = browser_stored_scan("asmt_bs", inv, _SB(), cap=6)
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "asmt_bs")).one()
    assert f.status == "validated" and "Stored/submitted XSS" in f.title


def test_browser_stored_noop_without_interact():
    from owlforge.engine.storedbrowser import browser_stored_scan
    assert browser_stored_scan("a", [{"url": "https://t", "source": "form"}], object()) == 0
