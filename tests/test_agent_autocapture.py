"""Auto-capture fallback: when a specialist CONFIRMS a vuln in its summary but never files it,
one model call extracts a structured finding and files it as a candidate (the evidence gate then
re-tests it, so a hallucinated extraction is filtered out downstream)."""
from __future__ import annotations

from owlforge.engine.agent import _auto_capture_finding


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
        return list(s.exec(select(Finding)))


class _Turn:
    def __init__(self, content):
        self.content = content
        self.tool_calls = []


class _Client:
    """Returns a scripted assistant turn; records the one chat() it receives."""
    def __init__(self, content):
        self._content = content
        self.calls = 0

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None):
        self.calls += 1
        self.prompt = "\n".join(m.content or "" for m in messages)
        return _Turn(self._content)


def test_auto_capture_files_candidate_from_summary(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    client = _Client(
        'Here is the finding: {"title":"Developer backdoor header grants admin",'
        '"severity":"critical","endpoint":"http://t/login",'
        '"proof_of_concept":"X-Dev-Access: yes flips a bad login into an authed session",'
        '"repro_method":"POST","repro_url":"http://t/login",'
        '"repro_params":{"X-Dev-Access":"yes"},"success_signal":"\\"token\\":"}'
    )
    ok = _auto_capture_finding(
        client, "asmt1", "http://t",
        "Confirmed: the X-Dev-Access header bypasses auth. I did not file it.",
        notes=["probed /login", "header turned 401 into 200"],
        actions=["POST /login X-Dev-Access: yes -> 200"],
        emit=lambda *a, **k: None,
    )
    assert ok is True
    found = _findings(db)
    assert len(found) == 1
    f = found[0]
    assert f.status == "candidate"
    assert f.severity == "critical"
    assert f.repro_url == "http://t/login"
    assert f.repro_params == {"X-Dev-Access": "yes"}
    assert f.success_signal and "token" in f.success_signal
    assert "auto-captured" in f.validation_note


def test_auto_capture_files_nothing_when_model_confirms_nothing(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    client = _Client("No vulnerability was actually confirmed. {}")
    ok = _auto_capture_finding(
        client, "asmt1", "http://t", "Tried several payloads, all rejected.",
        notes=["401 everywhere"], actions=["POST /login -> 401"],
        emit=lambda *a, **k: None,
    )
    assert ok is False
    assert _findings(db) == []


def test_auto_capture_rejects_finding_without_endpoint(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    client = _Client('{"title":"Something vague","severity":"high"}')
    ok = _auto_capture_finding(
        client, "asmt1", "http://t", "summary", notes=[], actions=[],
        emit=lambda *a, **k: None,
    )
    assert ok is False
    assert _findings(db) == []
