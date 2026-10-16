"""Auth Broker — SSO storage_state capture + cookie conversion."""

from __future__ import annotations

import types

from owlforge.engine.authbroker import capture_sso_session, storage_state_to_cookie


def test_storage_state_to_cookie_scopes_to_target_host():
    st = {"cookies": [
        {"name": "session", "value": "abc", "domain": ".abc.com"},
        {"name": "other", "value": "1", "domain": "evil.com"},
    ]}
    assert storage_state_to_cookie(st, "https://ui.abc.com/") == {"Cookie": "session=abc"}


class _FakeSandbox:
    def __init__(self, state):
        self.state = state
        self.started = self.finished = False

    def sso_start(self, url, *, headers=None):
        self.started = True
        return {"session_id": "sid1", "novnc_port": 6080, "novnc_path": "/vnc.html"}

    def sso_finish(self, session_id):
        self.finished = True
        return {"storage_state": self.state}


def test_capture_sso_session_persists_and_returns_state(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
    state = {"cookies": [{"name": "s", "value": "v", "domain": "t.com"}]}
    sb = _FakeSandbox(state)
    out = tmp_path / "sso.json"
    got = capture_sso_session(sb, "http://127.0.0.1:6080/vnc.html", "https://t.com/login",
                              persist_path=str(out), prompt_fn=lambda _m: "", log=lambda _m: None)
    assert sb.started and sb.finished
    assert got == state
    assert out.exists() and '"name": "s"' in out.read_text()


def test_capture_sso_skips_without_tty(monkeypatch):
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    sb = _FakeSandbox({"cookies": []})
    assert capture_sso_session(sb, "u", "https://t/login", prompt_fn=lambda _m: "", log=lambda _m: None) == {}
    assert not sb.started
