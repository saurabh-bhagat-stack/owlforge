"""TUI 2.0: passive hygiene findings collapse into one grouped row (press `h` to expand), so real
findings aren't buried — mirroring the stream's hygiene folding."""
from __future__ import annotations

from owlforge.engine.tui import ScanApp


def _rows():
    return [
        {"id": "f1", "severity": "high", "status": "validated", "title": "BOLA at /vehicle/{id}"},
        {"id": "f2", "severity": "info", "status": "candidate", "title": "Missing Content-Security-Policy"},
        {"id": "f3", "severity": "info", "status": "candidate", "title": "Clickjacking: no X-Frame-Options"},
        {"id": "f4", "severity": "info", "status": "candidate", "title": "Version disclosure via server"},
        {"id": "f5", "severity": "medium", "status": "candidate", "title": "Cookie without HttpOnly flag"},
    ]


def _app():
    return ScanApp("a", "http://t", "m", scan_fn=lambda emit, steer=None: ("s", None))


def test_hygiene_collapses_to_one_row():
    app = _app()
    app._show_hygiene = False
    out = app._group_hygiene(_rows())
    ids = [r["id"] for r in out]
    assert "f1" in ids                      # the real finding stays
    assert "__hygiene__" in ids             # 4 hygiene findings -> one grouped row
    assert all(h not in ids for h in ("f2", "f3", "f4", "f5"))
    grp = next(r for r in out if r["id"] == "__hygiene__")
    assert "Security hygiene (4)" in grp["title"]
    assert "Content-Security-Policy" in grp["technical_analysis"]


def test_expanded_shows_all():
    app = _app()
    app._show_hygiene = True
    out = app._group_hygiene(_rows())
    ids = [r["id"] for r in out]
    assert ids == ["f1", "f2", "f3", "f4", "f5"]   # no grouping when expanded
    assert "__hygiene__" not in ids


def test_no_hygiene_no_group_row():
    app = _app()
    app._show_hygiene = False
    out = app._group_hygiene([{"id": "f1", "severity": "high", "status": "validated",
                               "title": "SQL injection"}])
    assert [r["id"] for r in out] == ["f1"]        # nothing to group
