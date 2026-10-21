"""Client-side: postMessage (candidate) + subdomain takeover (validated)."""
from __future__ import annotations

from types import SimpleNamespace


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SBpm:
    """Serves a page whose inline script registers a message listener w/o origin check."""
    def __init__(self, with_origin=False):
        self.with_origin = with_origin
    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30_000):
        js = "window.addEventListener('message', function(e){ document.body.innerHTML = e.data; })"
        if self.with_origin:
            js = "window.addEventListener('message', function(e){ if(e.origin!=='x')return; foo(e.data); })"
        return {"status": 200, "final_url": url, "body": f"<html><script>{js}</script></html>"}


class _SBto:
    """host CNAMEs to github.io and serves the unclaimed fingerprint."""
    def exec(self, cmd, timeout_ms=0):
        return SimpleNamespace(stdout="victim.github.io.\n", stderr="", exit_code=0)
    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30_000):
        return {"status": 404, "final_url": url,
                "body": "There isn't a GitHub Pages site here."}


INV = [{"url": "https://t/app", "method": "GET", "params": [], "source": "link"}]


def test_postmessage_without_origin_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.clientside import postmessage_scan
    from owlforge.store.models import Finding
    assert postmessage_scan("a1", INV, _SBpm(with_origin=False), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert "postmessage" in f.title.lower() and f.status == "candidate"


def test_postmessage_with_origin_not_flagged(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.clientside import postmessage_scan
    assert postmessage_scan("a2", INV, _SBpm(with_origin=True), {}) == 0


def test_subdomain_takeover_validated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.clientside import subdomain_takeover_scan
    from owlforge.store.models import Finding
    n = subdomain_takeover_scan("a3", [], _SBto(), {}, target="https://blog.t.com/")
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a3")).one()
    assert "takeover" in f.title.lower() and f.status == "validated" and f.severity == "high"
