"""Per-role capability matrix: forced-browsing vertical privilege escalation."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _findings(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return s.exec(select(Finding).where(Finding.assessment_id == "a")).all()


USER = {"Cookie": "u=1"}
ADMIN = {"Cookie": "a=1"}
IDENTS = [{"label": "user", "role": "user", "headers": USER},
          {"label": "admin", "role": "admin", "headers": ADMIN}]
INV = [{"url": "https://t/admin/users", "method": "GET", "source": "link"}]
_DATA = "<table><tr><td>alice</td></tr><tr><td>bob</td></tr></table> user administration panel"


class _AdminApp:
    def __init__(self, enforce):
        self.enforce = enforce   # True = only admin may read; False = any user may (vuln)

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if not url.endswith("/admin/users"):
            return {"status": 404, "headers": {}, "body": "nf"}
        cookie = (headers or {}).get("Cookie", "")
        is_admin = cookie == "a=1"
        if self.enforce and not is_admin:
            return {"status": 403, "headers": {}, "body": "forbidden"}
        if not cookie:                                   # anonymous always denied here
            return {"status": 403, "headers": {}, "body": "forbidden"}
        return {"status": 200, "headers": {}, "body": _DATA}


def test_forced_browsing_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.rolematrix import capability_matrix_scan
    assert capability_matrix_scan("a", INV, _AdminApp(enforce=False), USER, IDENTS) >= 1
    f = _findings(db)
    assert any("lower-privilege role" in x.title.lower() and x.status == "candidate" for x in f)


def test_enforced_admin_is_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.rolematrix import capability_matrix_scan
    assert capability_matrix_scan("a", INV, _AdminApp(enforce=True), USER, IDENTS) == 0
    assert _findings(db) == []


def test_no_privileged_endpoints_noop(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.rolematrix import capability_matrix_scan
    inv = [{"url": "https://t/products", "method": "GET", "source": "link"}]
    assert capability_matrix_scan("a", inv, _AdminApp(enforce=False), USER, IDENTS) == 0
