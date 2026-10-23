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


# ---- schema-aware auth ------------------------------------------------------------------
class _AuthApp:
    """GET /api/admin: with enforce, requires auth (401 unauth); otherwise serves data."""

    def __init__(self, enforce):
        self.enforce = enforce

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/api/admin") and method == "GET":
            if self.enforce and not (headers or {}).get("Authorization") and not (headers or {}).get("Cookie"):
                return {"status": 401, "headers": {}, "body": "unauthorized"}
            return {"status": 200, "headers": {}, "body": "<users><u>alice</u><u>bob</u></users> admin data"}
        return {"status": 404, "headers": {}, "body": "nf"}


_PROTECTED = [{"url": "https://t/api/admin", "method": "GET", "source": "api-spec",
               "params": [], "requires_auth": True}]
_PUBLIC = [{"url": "https://t/api/admin", "method": "GET", "source": "api-spec",
            "params": [], "requires_auth": False}]


def test_api_missing_auth_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_auth_scan
    assert api_auth_scan("a", _PROTECTED, _AuthApp(enforce=False)) == 1
    assert any("without authentication" in f.title.lower() for f in _findings(db))


def test_api_auth_enforced_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_auth_scan
    assert api_auth_scan("a", _PROTECTED, _AuthApp(enforce=True)) == 0
    assert _findings(db) == []


def test_api_auth_skips_public_ops(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import api_auth_scan
    # even though it serves data unauth, the spec does not mark it protected -> not flagged
    assert api_auth_scan("a", _PUBLIC, _AuthApp(enforce=False)) == 0


# ---- method exposure (OPTIONS / Allow) --------------------------------------------------
class _OptionsApp:
    def __init__(self, allow):
        self.allow = allow

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if method == "OPTIONS":
            return {"status": 204, "headers": {"Allow": self.allow}, "body": ""}
        return {"status": 200, "headers": {}, "body": "ok"}


def test_method_exposure_flags_undocumented_delete(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import method_exposure_scan
    inv = [{"url": "https://t/api/orders", "method": "GET", "source": "api-spec"}]
    n = method_exposure_scan("a", inv, _OptionsApp("GET, DELETE, OPTIONS"), {})
    assert n == 1
    assert any("undocumented state-changing" in f.title.lower() for f in _findings(db))


def test_method_exposure_quiet_when_documented(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.apiabuse import method_exposure_scan
    # DELETE is documented (a second item), so advertising it is fine
    inv = [{"url": "https://t/api/orders", "method": "GET", "source": "api-spec"},
           {"url": "https://t/api/orders", "method": "DELETE", "source": "api-spec"}]
    assert method_exposure_scan("a", inv, _OptionsApp("GET, DELETE, OPTIONS"), {}) == 0
    assert _findings(db) == []
