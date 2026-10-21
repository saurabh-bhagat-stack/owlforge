"""Session fixation (session id not rotated on login)."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    """rotate=False -> same sessionid after login (fixation); rotate=True -> new value.
    login_ok controls whether the POST looks like a successful login."""
    def __init__(self, rotate=False, login_ok=True):
        self.rotate = rotate
        self.login_ok = login_ok

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30_000):
        if method == "GET":
            return {"status": 200, "set_cookie": ["sessionid=PRE123; Path=/; HttpOnly"],
                    "headers": {}, "body": "login form"}
        # POST login
        body_resp = "Welcome back" if self.login_ok else "invalid credentials"
        if self.rotate:
            sc = ["sessionid=NEW999; Path=/; HttpOnly"]
        else:
            sc = ["sessionid=PRE123; Path=/; HttpOnly"]   # unchanged -> fixation
        return {"status": 200, "set_cookie": sc, "headers": {}, "body": body_resp}


LOGIN = [{"url": "https://t/login", "data": "u=a&p=b", "success": "Welcome back"}]


def test_fixation_flagged_when_not_rotated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.sessionfix import session_fixation_scan
    from owlforge.store.models import Finding
    assert session_fixation_scan("a1", _SB(rotate=False, login_ok=True), LOGIN) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "fixation" in f.title.lower() and f.status == "validated"


def test_no_flag_when_rotated(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.sessionfix import session_fixation_scan
    assert session_fixation_scan("a2", _SB(rotate=True, login_ok=True), LOGIN) == 0


def test_no_flag_when_login_failed(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.sessionfix import session_fixation_scan
    # not rotated, but login did not succeed -> must NOT flag (would be a false positive)
    assert session_fixation_scan("a3", _SB(rotate=False, login_ok=False), LOGIN) == 0


def test_noop_without_login(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.sessionfix import session_fixation_scan
    assert session_fixation_scan("a4", _SB(), []) == 0
