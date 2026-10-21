"""Interactive Textual dashboard — headless (Pilot) checks."""
from __future__ import annotations

import asyncio


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def test_tui_populates_tracks_phase_and_opens_detail(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="f1", assessment_id="a", title="SQL injection (error-based)",
                      severity="high", status="validated", endpoint="https://t/catalog",
                      method="GET", proof_of_concept="category=1' -> 500",
                      technical_analysis="error-based", confidence="high"))
        s.commit()

    from textual.widgets import DataTable

    from owlforge.engine.tui import FindingDetail, ScanApp

    async def _run():
        app = ScanApp("a", "https://t", "modelX", scan_fn=lambda emit: ("summary", None))
        async with app.run_test() as pilot:
            app.on_scan_event("status", "orchestrator: 10 items -> 20 tasks")
            app._refresh()
            await pilot.pause()
            dt = app.query_one("#findings", DataTable)
            assert dt.row_count >= 1
            assert app._phase == "hunt"
            # open the detail screen for the seeded finding
            app.push_screen(FindingDetail(app._row_cache["f1"]))
            await pilot.pause()
            assert isinstance(app.screen, FindingDetail)

    asyncio.run(_run())


def test_phase_detection_helper():
    from owlforge.engine.tui import _phase_of
    assert _phase_of("[specialist:xss] testing") == "hunt"
    assert _phase_of("final validation sweep") == "validation"
    assert _phase_of("reporting phase") == "reporting"
    assert _phase_of("nothing special") is None
