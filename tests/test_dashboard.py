"""Live dashboard rendering + Emitter routing."""
from __future__ import annotations

import io

from rich.console import Console


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def test_emitter_routes_to_dashboard_not_console():
    seen = []

    class FakeDash:
        def handle(self, type_, message):
            seen.append((type_, message))

    from owlforge.engine.events import Emitter
    buf = io.StringIO()
    em = Emitter("a", console=Console(file=buf, no_color=True), persist=False, dashboard=FakeDash())
    em("status", "[specialist:xss] testing 3 target(s)")
    assert seen == [("status", "[specialist:xss] testing 3 target(s)")]
    assert buf.getvalue() == ""  # dashboard owns the screen; nothing printed inline


def test_dashboard_phase_tracking_and_render(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="f1", assessment_id="a", title="SQL injection (error-based)",
                      severity="high", status="validated", endpoint="https://t/catalog"))
        s.add(Finding(id="f2", assessment_id="a", title="Reflected XSS", severity="medium",
                      status="candidate", endpoint="https://t/search"))
        s.commit()

    from owlforge.engine.dashboard import Dashboard
    con = Console(file=io.StringIO(), width=120, height=40)
    d = Dashboard("a", "https://t", "modelX", con)
    d.handle("status", "orchestrator: 10 surface items -> 20 task(s)")
    assert d.phase == "hunt"
    d.handle("status", "validation phase")
    assert d.phase == "validation"

    rows = d._findings()
    assert rows and rows[0][1] == "validated"      # validated sorts first
    assert any(r[2] == "Reflected XSS" for r in rows)

    con.print(d.__rich__())                         # must render without raising
    out = con.file.getvalue()
    assert "owlforge" in out and "findings" in out
