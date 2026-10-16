"""Stored / second-order injection pass."""

from __future__ import annotations

import re


def test_stored_scan_validates_stored_xss(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    from sqlmodel import select

    from owlforge.engine.stored import stored_scan
    from owlforge.store.models import Finding

    class _Store:
        """Form POST 'stores' the payload; a later GET of /blog reflects it raw; it executes."""

        def __init__(self):
            self.stored = ""

        def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
            if method == "POST":
                self.stored = body or ""
                return {"status": 200, "body": "thanks"}
            if url.endswith("/blog"):
                m = re.search(r"owlstored[0-9a-f]+", self.stored)
                marker = m.group(0) if m else ""
                if marker:
                    inner = marker + '"><img src=x onerror="window.__owl_xss=' + "'" + marker + "'" + '">'
                    return {"status": 200, "body": "<div>" + inner + "</div>"}
                return {"status": 200, "body": "<div>empty</div>"}
            return {"status": 200, "body": "<form></form>"}

        def xss_check(self, url, token, *, headers=None, timeout_ms=15_000):
            return {"executed": True, "via": "script-exec (window.__owl_xss)", "status": 200}

    inv = [
        {"url": "https://t/blog/comment", "method": "POST", "params": ["comment", "name"], "source": "form"},
        {"url": "https://t/blog", "method": "GET", "params": [], "source": "link"},
    ]
    n = stored_scan("asmt_st", inv, _Store())
    assert n >= 1
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "asmt_st")).all()
    assert any(f.status == "validated" and "Stored XSS" in f.title for f in rows)
