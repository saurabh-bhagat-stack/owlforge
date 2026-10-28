"""Context-aware reflected XSS: JS-string breakout, attribute breakout, safe app."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from owlforge.engine.reflectxss import build_payload, classify, reflected_xss_scan


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _val(url):
    return next(iter(parse_qs(urlsplit(url).query).values()), [""])[0]


class _JS:
    """Reflects the param inside a single-quoted inline-script string, un-escaped."""
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "")
        return {"status": 200, "body": f"<script>var q='{v}';</script>"}

    def xss_check(self, url, token, *, headers=None, timeout_ms=30_000):
        v = _val(url)
        return {"executed": f"window.__owl_xss='{token}'" in v and v.startswith("';")}


class _Attr:
    """Reflects inside a double-quoted attribute, with < > " un-escaped (no browser)."""
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "")
        return {"status": 200, "body": f'<input value="{v}">'}


class _Safe:
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "")
        for a, b in (("<", "&lt;"), (">", "&gt;"), ('"', "&quot;"), ("'", "&#39;"), ("`", "&#96;")):
            v = v.replace(a, b)
        return {"status": 200, "body": f"<div>{v}</div>"}


def test_classify_js_string_context():
    ctx, info = classify("<script>var q='owlZ<>\"'`owlZ';</script>", "owlZ")
    assert ctx == "script" and info["quote"] == "'" and "'" in info["survived"]


def test_build_js_string_payload_breaks_out():
    pl = build_payload("script", {"survived": set("<>\"'`"), "quote": "'"}, "T")
    assert pl == "';window.__owl_xss='T';//"


def test_js_context_executes_and_files_validated(tmp_path, monkeypatch):
    from sqlmodel import select

    from owlforge.store.models import Finding
    db = _db(tmp_path, monkeypatch)
    n = reflected_xss_scan("a", [{"url": "https://t/p", "param": "q", "method": "GET"}], _JS())
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a")).one()
    assert f.status == "validated" and "script context" in f.title


def test_attribute_context_no_browser_files_candidate(tmp_path, monkeypatch):
    from sqlmodel import select

    from owlforge.store.models import Finding
    db = _db(tmp_path, monkeypatch)
    n = reflected_xss_scan("b", [{"url": "https://t/s", "param": "q", "method": "GET"}], _Attr())
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "b")).one()
    assert f.status == "candidate" and "tag context" in f.title


def test_safe_app_files_nothing(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    assert reflected_xss_scan("c", [{"url": "https://t/d", "param": "q", "method": "GET"}], _Safe()) == 0
