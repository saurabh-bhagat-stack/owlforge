"""Malicious upload (webshell/SVG) + stored injection (XSS/SSTI) via create flows."""
from __future__ import annotations

from urllib.parse import parse_qs


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _titles(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a")).all()]


# ---------- upload ----------
_UPLOAD_FORM = ('<form action="/upload" method="post" enctype="multipart/form-data">'
                '<input type="hidden" name="csrf" value="T">'
                '<input type="file" name="avatar"></form>')


class _UploadApp:
    """Stores an uploaded file and serves it at /uploads/<name>; `execute_php` toggles RCE."""

    def __init__(self, *, execute_php=False, serve_svg_inline=False):
        self.files = {}
        self.execute_php = execute_php
        self.serve_svg_inline = serve_svg_inline

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/upload") and method == "GET":
            return {"status": 200, "headers": {}, "body": _UPLOAD_FORM}
        if url.endswith("/upload") and method == "POST":
            # pull filename + content out of the multipart body
            import re
            mfn = re.search(r'filename="([^"]+)"', body or "")
            if not mfn:
                return {"status": 400, "headers": {}, "body": "no file"}
            fn = mfn.group(1)
            content = (body or "").split("\r\n\r\n", 2)[-1].rsplit("\r\n--", 1)[0]
            self.files[fn] = content
            return {"status": 200, "headers": {}, "body": f'ok: /uploads/{fn}'}
        if "/uploads/" in url and method == "GET":
            fn = url.rsplit("/", 1)[-1]
            if fn not in self.files:
                return {"status": 404, "headers": {}, "body": ""}
            content = self.files[fn]
            if fn.endswith((".php", ".phtml", ".php5")) and self.execute_php:
                import re
                m = re.search(r"echo '([^']+)'", content)
                return {"status": 200, "headers": {"content-type": "text/html"},
                        "body": (m.group(1) if m else "")}      # EXECUTED output, not source
            if fn.endswith(".svg"):
                ct = "image/svg+xml" if self.serve_svg_inline else "application/octet-stream"
                return {"status": 200, "headers": {"content-type": ct}, "body": content}
            return {"status": 200, "headers": {"content-type": "text/plain"}, "body": content}
        return {"status": 404, "headers": {}, "body": ""}


_UP_INV = [{"url": "https://t/upload", "method": "POST", "source": "form", "params": ["avatar"]}]


def test_webshell_upload_rce(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.maliciousdata import malicious_upload_scan
    n = malicious_upload_scan("a", _UP_INV, _UploadApp(execute_php=True), {"Cookie": "s=1"})
    assert n >= 1 and any("RCE" in t for t in _titles(db))


def test_svg_upload_stored_xss(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.maliciousdata import malicious_upload_scan
    n = malicious_upload_scan("a", _UP_INV, _UploadApp(serve_svg_inline=True), {"Cookie": "s=1"})
    assert n >= 1 and any("Stored XSS via file upload" in t for t in _titles(db))


def test_secure_upload_no_findings(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.maliciousdata import malicious_upload_scan
    assert malicious_upload_scan("a", _UP_INV, _UploadApp(), {"Cookie": "s=1"}) == 0
    assert _titles(db) == []


# ---------- stored injection ----------
_CREATE_FORM = ('<form action="/comments/create" method="post">'
                '<input type="hidden" name="csrf" value="T">'
                '<textarea name="body"></textarea></form>')


class _CommentApp:
    """Stores a comment and reflects it on GET; `ssti` evaluates templates, `encode` escapes."""

    def __init__(self, *, ssti=False, encode=False):
        self.stored = ""
        self.ssti = ssti
        self.encode = encode

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/comments/create") and method == "GET":
            shown = self.stored
            if self.ssti and "1337*1337" in shown:
                shown = shown.replace("{{1337*1337}}", "1787569")
            if self.encode:
                shown = shown.replace("<", "&lt;").replace(">", "&gt;")
            return {"status": 200, "headers": {}, "body": f"<div>{shown}</div>" + _CREATE_FORM}
        if url.endswith("/comments/create") and method == "POST":
            self.stored = parse_qs(body or "").get("body", [""])[0]
            return {"status": 302, "headers": {"location": "/comments/create"}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}


_CR_INV = [{"url": "https://t/comments/create", "method": "POST", "source": "form", "params": ["body"]}]


def test_stored_xss_raw_reflection(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.maliciousdata import stored_injection_scan
    n = stored_injection_scan("a", _CR_INV, _CommentApp(), {"Cookie": "s=1"})
    assert n >= 1 and any("Stored XSS" in t for t in _titles(db))


def test_stored_ssti(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.maliciousdata import stored_injection_scan
    n = stored_injection_scan("a", _CR_INV, _CommentApp(ssti=True), {"Cookie": "s=1"})
    assert n >= 1 and any("template injection" in t for t in _titles(db))


def test_encoded_output_no_finding(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.maliciousdata import stored_injection_scan
    assert stored_injection_scan("a", _CR_INV, _CommentApp(encode=True), {"Cookie": "s=1"}) == 0
