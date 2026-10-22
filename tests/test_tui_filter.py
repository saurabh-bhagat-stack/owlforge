"""Dashboard filter + sort."""
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


def _rows():
    return [
        {"id": "a", "severity": "critical", "status": "validated", "title": "RCE", "endpoint": "/x"},
        {"id": "b", "severity": "high", "status": "validated", "title": "SQL injection", "endpoint": "/s"},
        {"id": "c", "severity": "low", "status": "candidate", "title": "Missing CSP", "endpoint": "/"},
        {"id": "d", "severity": "medium", "status": "candidate", "title": "CSRF", "endpoint": "/f"},
    ]


def test_apply_view_filter_and_sort():
    from owlforge.engine.tui import ScanApp
    app = ScanApp("a", "t", "m", scan_fn=lambda e: (None, None))

    # severity floor: only high+critical
    app._min_sev, app._filter, app._sort_key = 3, "", "sev"
    ids = [f["id"] for f in app._apply_view(_rows())]
    assert ids == ["a", "b"]                       # critical first, then high

    # text filter
    app._min_sev, app._filter = -1, "csrf"
    assert [f["id"] for f in app._apply_view(_rows())] == ["d"]

    # sort by title
    app._filter, app._sort_key = "", "title"
    titles = [f["title"] for f in app._apply_view(_rows())]
    assert titles == sorted(titles, key=str.lower)


def test_filter_sort_keys_drive_the_table(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.store.models import Finding
    with db.session() as s:
        for r in _rows():
            s.add(Finding(id=r["id"], assessment_id="a", title=r["title"], severity=r["severity"],
                          status=r["status"], endpoint=r["endpoint"]))
        s.commit()

    from textual.widgets import DataTable

    from owlforge.engine.tui import ScanApp

    async def _run():
        app = ScanApp("a", "t", "m", scan_fn=lambda e: (None, None))
        async with app.run_test(size=(100, 24)) as pilot:
            app._refresh()
            await pilot.pause()
            dt = app.query_one("#findings", DataTable)
            assert dt.row_count == 4

            await pilot.press("v")        # all -> low+ (>=1): still all 4 (none below low)
            await pilot.press("v")        # -> medium+ : drops the low (3)
            await pilot.pause()
            assert dt.row_count == 3 and app._min_sev == 2

            await pilot.press("s")        # cycle sort key
            await pilot.pause()
            assert app._sort_key == "status"

            # apply a text filter programmatically via the submit handler
            app._min_sev = -1
            app.query_one("#filter").value = "sql"
            from textual.widgets import Input
            app.on_input_submitted(Input.Submitted(app.query_one("#filter"), "sql"))
            await pilot.pause()
            assert dt.row_count == 1

    asyncio.run(_run())


def test_steer_queues_notes_for_the_orchestrator(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    import asyncio

    from textual.widgets import Input

    from owlforge.engine.tui import ScanApp

    async def _run():
        app = ScanApp("a", "t", "m", scan_fn=lambda e, s: (None, None))
        async with app.run_test(size=(100, 24)) as pilot:
            await pilot.pause()
            # submit a steer note the way the Input would
            app.on_input_submitted(Input.Submitted(app.query_one("#steer"), "focus on /api/admin"))
            await pilot.pause()
            drained = app.drain_steer()
            assert drained == ["focus on /api/admin"]
            assert app.drain_steer() == []          # cleared after draining

    asyncio.run(_run())


def test_auth_modal_opens_and_signals_done(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    import asyncio
    import threading

    from owlforge.engine.tui import AuthModal, ScanApp

    async def _run():
        app = ScanApp("a", "t", "m", scan_fn=lambda e, s: (None, None))
        async with app.run_test(size=(100, 24)) as pilot:
            await pilot.pause()
            ev = threading.Event()
            app.pause_for_auth("http://127.0.0.1:6080/vnc.html", ev)
            await pilot.pause()
            assert isinstance(app.screen, AuthModal)
            await pilot.press("enter")          # operator finished the login
            await pilot.pause()
            assert ev.is_set()                  # worker is unblocked
            assert not isinstance(app.screen, AuthModal)

    asyncio.run(_run())
