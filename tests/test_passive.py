"""Passive security checks."""

from __future__ import annotations

from owlforge.engine.passive import cors_reflection, host_header_injection, scan_response


def test_scan_response_flags_headers_cookies_cors_version_dirlisting():
    resp = {
        "headers": {
            "Server": "nginx/1.18.0",
            "Set-Cookie": "sessionid=abc; Path=/",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        "body": "<title>Index of /files</title> Index of /files",
    }
    titles = {f.title for f in scan_response("https://t/", resp)}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing HSTS" in titles
    assert any("Secure flag" in t for t in titles)
    assert any("HttpOnly flag" in t for t in titles)
    assert "Permissive CORS: wildcard origin with credentials" in titles
    assert "Version disclosure via server" in titles
    assert "Directory listing enabled" in titles


def test_scan_response_quiet_when_hardened():
    resp = {
        "headers": {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "Set-Cookie": "sid=x; Secure; HttpOnly; SameSite=Lax",
        },
        "body": "<html>ok</html>",
    }
    assert scan_response("https://t/", resp) == []


def test_cors_reflection_probe():
    def reqfn(method, url, headers=None, params=None, body=None):
        origin = (headers or {}).get("Origin", "")
        return {"headers": {"Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true"}, "body": ""}
    pf = cors_reflection("https://t/", reqfn)
    assert pf and pf.severity == "high" and "Reflected-origin" in pf.title


def test_passive_scan_files_findings(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    from sqlmodel import select

    from owlforge.engine.passive import passive_scan
    from owlforge.store.models import Finding

    def reqfn(method, url, headers=None, params=None, body=None):
        return {"headers": {"Server": "Apache/2.4.1"}, "body": "ok"}

    n = passive_scan("asmt_p", "https://t/", [], reqfn)
    assert n > 0
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "asmt_p")).all()
    assert all(f.status == "candidate" and f.validation_note == "passive observation (deterministic)" for f in rows)


def test_host_header_injection_probe():
    def reqfn(method, url, headers=None, params=None, body=None):
        h = (headers or {}).get("Host", "")
        return {"headers": {"Location": f"https://{h}/reset?token=abc"}, "body": ""}
    pf = host_header_injection("https://t/", reqfn)
    assert pf and pf.severity == "medium" and "Host-header" in pf.title


def test_deserialization_blob_detected():
    from owlforge.engine.passive import scan_response
    titles = {f.title for f in scan_response("https://t/", {"headers": {"Set-Cookie": "state=rO0ABXNy"}, "body": ""})}
    assert any("deserialization" in x.lower() for x in titles)


def test_session_cookie_never_expires_flagged():
    from owlforge.engine.passive import scan_response
    far = {"headers": {"Set-Cookie": "session=abc; Expires=Sun, 07 Jul 2058 22:34:53 GMT; "
                       "HttpOnly; SameSite=Lax; Secure; Path=/"}}
    titles = {f.title for f in scan_response("https://t/", far)}
    assert any("never expires" in t for t in titles)     # the "old sessions" class


def test_session_cookie_properly_scoped_is_quiet():
    from owlforge.engine.passive import scan_response
    # session-scoped (no Expires) and a short Max-Age must NOT be flagged for lifetime
    scoped = {"headers": {"Set-Cookie": "session=abc; HttpOnly; SameSite=Lax; Secure; Path=/"}}
    short = {"headers": {"Set-Cookie": "session=abc; Max-Age=3600; HttpOnly; SameSite=Lax; Secure"}}
    for resp in (scoped, short):
        assert not any("never expires" in f.title for f in scan_response("https://t/", resp))
