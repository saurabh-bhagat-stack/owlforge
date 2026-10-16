"""Attempt ledger + the bypass nudge (don't give up on a confirmed signal)."""

from __future__ import annotations

import asyncio

from owlforge.engine.agent import run_single_agent
from owlforge.engine.events import Emitter
from owlforge.llm.base import AssistantTurn, ToolCall
from owlforge.tools.base import Tool, ToolRegistry


def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import owlforge.config as config
    import owlforge.store.db as db
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def test_attempt_ledger_record_and_summary(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    from owlforge.engine.ledger import attempts_summary, record_attempt

    record_attempt("asmt_l", "https://t/c", "GET", {"category": "'"}, 500, note="quote->500")
    record_attempt("asmt_l", "https://t/c", "GET", {"category": "''"}, 200)
    out = attempts_summary("asmt_l", url="https://t/c")
    assert "500" in out and "200" in out and "category" in out


class _FakeClient:
    def __init__(self, turns):
        self._t = turns
        self.calls = 0

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None):
        t = self._t[min(self.calls, len(self._t) - 1)]
        self.calls += 1
        return t


def _finish_only_registry():
    async def _finish(args, ctx):
        return "done"
    reg = ToolRegistry()
    reg.add(Tool(name="finish", description="f", parameters={"type": "object", "properties": {}},
                 run=_finish, lifecycle=True))
    return reg


def _run(client, tmp_path, monkeypatch, **kw):
    _isolated(tmp_path, monkeypatch)
    return asyncio.run(run_single_agent(
        client=client, registry=_finish_only_registry(), emit=Emitter("asmt_b", persist=False),
        assessment_id="asmt_b", target="https://t", instructions="test", scan_mode="quick",
        max_turns=5, **kw))


def test_bypass_nudge_fires_on_confirmed_signal(tmp_path, monkeypatch):
    def fin(i):
        return AssistantTurn(content=None, tool_calls=[ToolCall(id=f"f{i}", name="finish",
                             arguments={"summary": "done"})])
    c = _FakeClient([fin(1), fin(2)])
    _run(c, tmp_path, monkeypatch, expected_signal="category: single-quote -> 500")
    assert c.calls == 2   # first finish was intercepted by the bypass nudge, model re-prompted


def test_no_bypass_nudge_without_signal(tmp_path, monkeypatch):
    c = _FakeClient([AssistantTurn(content=None,
                     tool_calls=[ToolCall(id="f1", name="finish", arguments={"summary": "done"})])])
    _run(c, tmp_path, monkeypatch, expected_signal="")
    assert c.calls == 1   # no signal -> finish is honored immediately
