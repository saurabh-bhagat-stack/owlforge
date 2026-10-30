"""The sandbox client retries connection-level failures to the local agentd (a transient blip
under load must not collapse a tool call / the whole authed assessment)."""
from __future__ import annotations

import httpx
import pytest

from owlforge.sandbox.client import SandboxClient


class _Resp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


def _flaky(fail_times, data, exc=httpx.ConnectError):
    calls = {"n": 0}

    def post(url, **kw):
        if calls["n"] < fail_times:
            calls["n"] += 1
            raise exc("boom")
        return _Resp(data)
    return post, calls


def test_http_request_retries_then_succeeds(monkeypatch):
    post, calls = _flaky(2, {"status": 200, "body": "ok"})
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr("owlforge.sandbox.client.time.sleep", lambda *_: None)
    c = SandboxClient("http://127.0.0.1:1", token="t")
    r = c.http_request("GET", "http://target/")
    assert r == {"status": 200, "body": "ok"}
    assert calls["n"] == 2            # failed twice, succeeded on the 3rd


def test_exec_retries_then_succeeds(monkeypatch):
    data = {"exit_code": 0, "stdout": "hi", "stderr": "", "duration_ms": 1}
    post, calls = _flaky(1, data, exc=httpx.RemoteProtocolError)
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr("owlforge.sandbox.client.time.sleep", lambda *_: None)
    c = SandboxClient("http://127.0.0.1:1", token="t")
    out = c.exec("echo hi")
    assert out.stdout == "hi" and out.exit_code == 0
    assert calls["n"] == 1


def test_persistent_connect_error_still_raises(monkeypatch):
    post, _ = _flaky(99, {"status": 200})
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr("owlforge.sandbox.client.time.sleep", lambda *_: None)
    c = SandboxClient("http://127.0.0.1:1", token="t")
    with pytest.raises(httpx.ConnectError):
        c.http_request("GET", "http://target/")


def test_non_transient_error_not_retried(monkeypatch):
    calls = {"n": 0}

    def post(url, **kw):
        calls["n"] += 1
        raise httpx.ReadTimeout("slow")      # a real timeout = the command ran long; do NOT retry
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr("owlforge.sandbox.client.time.sleep", lambda *_: None)
    c = SandboxClient("http://127.0.0.1:1", token="t")
    with pytest.raises(httpx.ReadTimeout):
        c.http_request("GET", "http://target/")
    assert calls["n"] == 1               # tried once, not retried
