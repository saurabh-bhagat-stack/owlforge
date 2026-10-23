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


def test_storage_state_to_headers_extracts_bearer():
    from owlforge.engine.authbroker import storage_state_to_headers
    state = {"cookies": [{"name": "sid", "value": "x", "domain": "app.local"}],
             "origins": [{"localStorage": [
                 {"name": "access_token", "value": "abcd1234.efgh5678.ijkl9012"}]}]}
    h = storage_state_to_headers(state, "https://app.local")
    assert h["Authorization"] == "Bearer abcd1234.efgh5678.ijkl9012"
    assert "sid=x" in h["Cookie"]


def test_storage_state_to_headers_bearer_from_json_value():
    from owlforge.engine.authbroker import storage_state_to_headers
    state = {"cookies": [], "origins": [{"localStorage": [
        {"name": "auth", "value": '{"access_token":"aaaa1111.bbbb2222.cccc3333"}'}]}]}
    h = storage_state_to_headers(state, "https://app.local")
    assert h.get("Authorization") == "Bearer aaaa1111.bbbb2222.cccc3333"


def test_load_persisted_session(tmp_path):
    import json

    from owlforge.engine.authbroker import load_persisted_session
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"cookies": [{"name": "a", "value": "b", "domain": "d"}]}))
    assert load_persisted_session(str(p))["cookies"][0]["name"] == "a"
    assert load_persisted_session(str(tmp_path / "missing.json")) == {}
    assert load_persisted_session(None) == {}


_SAVED = {"cookies": [{"name": "sid", "value": "s", "domain": "app.local"}]}


def test_reuse_sso_when_session_alive(tmp_path):
    import json

    from owlforge.engine.authbroker import reuse_or_capture_sso
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_SAVED))

    def _no_capture(*a, **k):
        raise AssertionError("must not re-capture when the saved session is alive")

    st = reuse_or_capture_sso(None, "novnc", "https://app.local/login",
                              target="https://app.local", persist_path=str(p),
                              is_alive=lambda h: True, capture_fn=_no_capture)
    assert st == _SAVED


def test_recapture_sso_when_stale(tmp_path):
    import json

    from owlforge.engine.authbroker import reuse_or_capture_sso
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_SAVED))
    seen = {}

    def _cap(sc, nv, lu, *, persist_path=None, prompt_fn=None, log=None):
        seen["called"] = True
        return {"captured": 1}

    st = reuse_or_capture_sso(None, "novnc", "u", target="https://app.local",
                              persist_path=str(p), is_alive=lambda h: False, capture_fn=_cap)
    assert seen.get("called") and st == {"captured": 1}


def test_capture_sso_when_no_saved_session(tmp_path):
    from owlforge.engine.authbroker import reuse_or_capture_sso

    def _cap(sc, nv, lu, *, persist_path=None, prompt_fn=None, log=None):
        return {"captured": 1}

    st = reuse_or_capture_sso(None, "novnc", "u", target="https://app.local",
                              persist_path=str(tmp_path / "none.json"),
                              is_alive=lambda h: True, capture_fn=_cap)
    assert st == {"captured": 1}
