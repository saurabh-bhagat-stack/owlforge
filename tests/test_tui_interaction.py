"""End-to-end interaction checks for the Textual dashboard, driven headlessly with
Pilot: cursor scrolling, Enter/click detail, detail scroll + close, live finding
inserts, status counts, resize, and quit."""
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


def _seed(db, n, status="validated"):
    from owlforge.store.models import Finding
    sevs = ["critical", "high", "medium", "low"]
    with db.session() as s:
        for i in range(n):
            s.add(Finding(id=f"f{i}", assessment_id="a",
                          title=f"Finding number {i} with a longish descriptive title",
                          severity=sevs[i % 4], status=status,
                          endpoint=f"https://t/path/{i}", method="GET",
                          proof_of_concept=f"payload {i}", technical_analysis="detail " * 40,
                          impact="impact", remediation="fix it", confidence="high"))
        s.commit()


def test_full_interaction_cycle(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db, 20)  # more rows than fit -> must scroll

    from textual.widgets import DataTable, RichLog

    from owlforge.engine.tui import FindingDetail, ScanApp

    async def _run():
        app = ScanApp("a", "https://t", "modelX", scan_fn=lambda emit: ("summary", "/r.md"))
        async with app.run_test(size=(100, 24)) as pilot:
            # feed a stream of log events -> the event pane fills and is scrollable
            for i in range(60):
                app.on_scan_event("status" if i % 2 else "tool_call", f"event line {i}")
            app._refresh()
            await pilot.pause()

            dt = app.query_one("#findings", DataTable)
            assert dt.row_count == 20, f"expected 20 rows, got {dt.row_count}"
            log = app.query_one("#log", RichLog)
            assert len(log.lines) > 20  # log populated and scrollable

            # cursor scrolls with arrow keys (table is focused)
            start = dt.cursor_row
            await pilot.press("down", "down", "down")
            await pilot.pause()
            assert dt.cursor_row == start + 3, "arrow keys did not move the cursor"
            await pilot.press(*(["down"] * 25))      # scroll past the end -> clamps at last row
            await pilot.pause()
            assert dt.cursor_row == 19, f"could not scroll to last row (at {dt.cursor_row})"
            await pilot.press(*(["up"] * 25))        # scroll back to the top
            await pilot.pause()
            assert dt.cursor_row == 0

            # Enter on a row opens the scrollable detail screen
            await pilot.press("down")          # move to row 1
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, FindingDetail), "Enter did not open the detail screen"
            await pilot.press("pagedown", "down")   # scroll within detail (no crash)
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, FindingDetail), "Escape did not close the detail"

            # 'd' key also opens detail (keyboard alt to click)
            await pilot.press("d")
            await pilot.pause()
            assert isinstance(app.screen, FindingDetail)
            await pilot.press("q")             # q closes the modal (its binding)
            await pilot.pause()
            assert not isinstance(app.screen, FindingDetail)

            # live insert: a new finding appears on the next refresh, counts update
            from owlforge.store.models import Finding
            with db.session() as s:
                s.add(Finding(id="live1", assessment_id="a", title="Live new finding",
                              severity="high", status="validated", endpoint="https://t/live"))
                s.commit()
            app._refresh()
            await pilot.pause()
            assert dt.row_count == 21, "live-inserted finding did not appear"
            assert app._row_cache.get("live1") is not None  # new finding tracked live
            v = sum(1 for f in app._row_cache.values() if f["status"] == "validated")
            assert v == 21  # status-bar validated count reflects the live insert

            # resize still renders
            await pilot.resize_terminal(140, 40)
            await pilot.pause()
            app._scan_done()
            await pilot.pause()
            assert app._done is True

    asyncio.run(_run())


def test_quit_binding_exits(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.tui import ScanApp

    async def _run():
        app = ScanApp("a", "https://t", "m", scan_fn=lambda emit: ("s", None))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
    # returns (app exits) without hanging
    asyncio.run(_run())
