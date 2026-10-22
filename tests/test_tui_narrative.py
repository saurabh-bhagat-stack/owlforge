"""Narrative feed, current-target card, surface panel, raw-log."""
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


def test_narrate_rules():
    from owlforge.engine.tui import narrate
    assert "SQL injection" in narrate("status", "[specialist:sqli] testing 6 target(s)").plain
    assert narrate("status", "[specialist:xss] skipped (pre-probe found no signal)") is None
    assert "thinking" in narrate("think", "plan: test category").plain
    assert "confirmed" in narrate("finding_validated", "VALIDATED: RCE").plain
    assert narrate("tool_result", "-> status=200") is None          # boring 200 folded
    assert "500" in narrate("tool_result", "-> status=500").plain
    assert "recon" in narrate("status", "recon-summary: mapped 128 endpoint(s); authed").plain


def test_surface_target_and_rawlog(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.store.models import Finding, SurfaceItem
    with db.session() as s:
        s.add(SurfaceItem(id="s1", assessment_id="a", url="https://t/catalog?category=1",
                          method="GET", params=["category"], source="link"))
        s.add(Finding(id="f1", assessment_id="a", title="SQLi", severity="high",
                      status="validated", endpoint="https://t/catalog"))
        s.commit()

    from textual.widgets import DataTable

    from owlforge.engine.tui import RawLogScreen, ScanApp

    async def _run():
        app = ScanApp("a", "https://t", "m", scan_fn=lambda e, s: (None, None))
        async with app.run_test(size=(140, 40)) as pilot:
            # a probe updates the current-target card + raw buffer
            app.on_scan_event("status", "[specialist:sqli] testing 3 target(s)")
            app.on_scan_event("tool_call", "http_request GET https://t/catalog?category=1")
            app._refresh()
            await pilot.pause()
            assert app._cur_target.endswith("category=1") and app._cur_class == "sqli"
            assert app.query_one("#surface", DataTable).row_count == 1   # surface populated
            assert app.query_one("#findings", DataTable).row_count == 1
            assert len(app._raw) >= 2

            await pilot.press("l")                                       # raw-log screen
            await pilot.pause()
            assert isinstance(app.screen, RawLogScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, RawLogScreen)

    asyncio.run(_run())


def test_steer_input_is_persistent(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from textual.widgets import Input

    from owlforge.engine.tui import ScanApp

    async def _run():
        app = ScanApp("a", "t", "m", scan_fn=lambda e, s: (None, None))
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            assert app.query_one("#steer", Input).display is True        # always visible
            app.on_input_submitted(Input.Submitted(app.query_one("#steer"), "focus on /api"))
            await pilot.pause()
            assert app.drain_steer() == ["focus on /api"]

    asyncio.run(_run())
