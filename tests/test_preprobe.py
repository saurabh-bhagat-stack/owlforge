"""Deterministic pre-probe (LLM gating)."""

from __future__ import annotations

from owlforge.engine.classify import CSRF, PATH, RCE, SQLI, SSRF, SSTI, XSS
from owlforge.engine.preprobe import filter_targets, probe


class _SB:
    """Stub sandbox: category' -> 500; q reflects raw; file returns /etc/passwd; url reflects in Location."""
    def http_request(self, method, url, *, params=None, headers=None, body=None, timeout_ms=60_000):
        params = params or {}
        if params.get("category", "") == "1'":
            return {"status": 500, "body": "SQL error"}
        if "category" in params:
            return {"status": 200, "body": "ok" * 80}
        if "q" in params:
            return {"status": 200, "body": f"result: {params['q']} done"}
        if "file" in params:
            body = "root:x:0:0:root:/root:/bin/bash" if ".." in params["file"] else "home"
            return {"status": 200, "body": body}
        if "next" in params:
            return {"status": 302, "headers": {"Location": params["next"]}, "body": ""}
        return {"status": 200, "body": "x"}


def test_probe_detects_each_gateable_class():
    sb = _SB()
    assert probe(SQLI, {"url": "https://t/c", "param": "category"}, sb)[0] is True
    assert probe(XSS, {"url": "https://t/s", "param": "q"}, sb)[0] is True
    assert probe(PATH, {"url": "https://t/d", "param": "file"}, sb)[0] is True
    assert probe(SSRF, {"url": "https://t/r", "param": "next"}, sb)[0] is True


def test_probe_negative_when_no_signal():
    class Quiet:
        def http_request(self, method, url, *, params=None, headers=None, body=None, timeout_ms=60_000):
            return {"status": 200, "body": "nothing interesting"}
    assert probe(SQLI, {"url": "https://t/c", "param": "x"}, Quiet())[0] is False
    assert probe(XSS, {"url": "https://t/c", "param": "x"}, Quiet())[0] is False


def test_filter_targets_gates_gateable_passes_through_others():
    sb = _SB()
    sqli_targets = [{"url": "https://t/c", "param": "category"}, {"url": "https://t/c", "param": "x"}]
    kept, notes = filter_targets(SQLI, sqli_targets, sb)
    assert [t["param"] for t in kept] == ["category"] and notes          # only the one with signal
    # non-gateable class passes through untouched (differential handled later)
    csrf_targets = [{"url": "https://t/login", "param": None}]
    kept2, notes2 = filter_targets(CSRF, csrf_targets, sb)
    assert kept2 == csrf_targets and notes2 == []


def test_probe_ssti_and_rce():
    class SSTISB:
        def http_request(self, method, url, *, params=None, headers=None, body=None, timeout_ms=60_000):
            v = (params or {}).get("name", "")
            body = "Hello 1787569!" if "1337*1337" in v else "Hello there"
            return {"status": 200, "body": body}
    assert probe(SSTI, {"url": "https://t/greet", "param": "name"}, SSTISB())[0] is True

    class RCESB:
        def http_request(self, method, url, *, params=None, headers=None, body=None, timeout_ms=60_000):
            v = (params or {}).get("host", "")
            hit = "id" in v and any(ch in v for ch in ";|$`")
            body = "uid=33(www-data) gid=33(www-data)" if hit else "pong"
            return {"status": 200, "body": body}
    assert probe(RCE, {"url": "https://t/ping", "param": "host"}, RCESB())[0] is True

    class Quiet:
        def http_request(self, method, url, *, params=None, headers=None, body=None, timeout_ms=60_000):
            return {"status": 200, "body": "nothing"}
    assert probe(SSTI, {"url": "https://t/x", "param": "p"}, Quiet())[0] is False
    assert probe(RCE, {"url": "https://t/x", "param": "p"}, Quiet())[0] is False
