"""rolematrix SPA catch-all detector: an SPA shell served for every route is not a finding."""
from __future__ import annotations

from owlforge.engine.rolematrix import _is_shell, capability_matrix_scan


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _count(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return len(list(s.exec(select(Finding))))


_INV = [{"url": "https://t/admin", "method": "GET", "params": []}]


class _SPA:
    """Every route — real or bogus — returns the same client-rendered shell."""
    SHELL = ("<html><body><app-root></app-root>"
             "<script src='/main.js'></script></body></html>") * 4

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        return {"status": 200, "headers": {}, "body": self.SHELL}


class _RealAdmin:
    """Bogus paths 404; /admin returns distinct admin content (genuinely unprotected)."""

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if "/admin-" in url:                       # the random catch-all probe paths
            return {"status": 404, "headers": {}, "body": "nope"}
        if url.rstrip("/").endswith("/admin"):
            return {"status": 200, "headers": {}, "body": "<h1>Admin Dashboard</h1>" + "x" * 200}
        return {"status": 404, "headers": {}, "body": ""}


def test_is_shell_matches_normalised_body():
    shell = "<html> <app-root></app-root> </html>"
    assert _is_shell("<html>\n<app-root></app-root>\n</html>", "".join(shell.split()))


def test_spa_catchall_suppresses_false_privileged_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    filed = capability_matrix_scan("a", _INV, _SPA(), {}, [])
    assert filed == 0                              # the shell is not a reachable endpoint
    assert _count(db) == 0


def test_real_unprotected_admin_still_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    filed = capability_matrix_scan("a", _INV, _RealAdmin(), {}, [])
    assert filed == 1                              # distinct admin content reachable by anon
    assert _count(db) == 1
