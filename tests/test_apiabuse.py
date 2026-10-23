"""API body/variable fuzzing on JSON endpoints."""
from __future__ import annotations

import json


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


SESS = {"Cookie": "s=1"}
INV = [{"url": "https://t/api/render", "method": "POST", "params": ["name"], "source": "api-spec"}]


class _ApiApp:
    def __init__(self, ssti=False, sqli=False):
        self.ssti = ssti
        self.sqli = sqli

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        obj = json.loads(body or "{}")
        name = str(obj.get("name", ""))
        if self.sqli and "'" in name:
            return {"status": 500, "headers": {}, "body": "You have an error in your SQL syntax"}
        if self.ssti and "{{1337*1337}}" in name:
            return {"status": 200, "headers": {}, "body": "Hello 1787569"}
        return {"status": 200, "headers": {}, "body": f"Hello {name}"}


def test_api_ssti_in_json_body_validated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_fuzz_scan
    assert api_fuzz_scan("a", INV, _ApiApp(ssti=True), SESS) >= 1
    assert any("template injection" in f.title.lower() and f.status == "validated"
               for f in _findings(db))


def test_api_sqli_error_differential_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_fuzz_scan
    assert api_fuzz_scan("a", INV, _ApiApp(sqli=True), SESS) >= 1
    assert any("sql injection" in f.title.lower() for f in _findings(db))


def test_api_secure_is_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_fuzz_scan
    assert api_fuzz_scan("a", INV, _ApiApp(), SESS) == 0
    assert _findings(db) == []


def test_api_fuzz_ignores_non_api_and_no_sandbox(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_fuzz_scan
    html_inv = [{"url": "https://t/contact", "method": "POST", "params": ["msg"], "source": "form"}]
    assert api_fuzz_scan("a", html_inv, _ApiApp(ssti=True), SESS) == 0
    assert api_fuzz_scan("a", INV, None, SESS) == 0
