"""Phase 1 tests: tool-call parsing, context trimming, and the agent loop (no network)."""

from __future__ import annotations

import asyncio

from owlforge.engine.agent import run_single_agent
from owlforge.engine.events import Emitter
from owlforge.llm.base import AssistantTurn, Message, ToolCall
from owlforge.llm.context import trim_messages
from owlforge.llm.toolproto import parse_tool_calls
from owlforge.tools.base import Tool, ToolRegistry


def test_parse_fenced_and_bare_and_none():
    names = {"http_fetch", "finish"}
    leftover, calls = parse_tool_calls(
        'thinking...\n```json\n{"tool":"http_fetch","args":{"url":"x"}}\n```', names
    )
    assert calls and calls[0].name == "http_fetch" and calls[0].arguments["url"] == "x"

    _, calls = parse_tool_calls('{"tool":"finish","args":{"summary":"done"}}', names)
    assert calls and calls[0].name == "finish"

    leftover, calls = parse_tool_calls("just prose, no tool", names)
    assert calls == [] and leftover


def test_trim_keeps_system_and_recent():
    msgs = [Message(role="system", content="S" * 40)]
    msgs += [Message(role="user", content="U" * 400) for _ in range(50)]
    trimmed = trim_messages(msgs, context_window=1000, reserve_for_output=200)
    assert trimmed[0].role == "system"
    assert len(trimmed) < len(msgs)  # older messages dropped


class _FakeClient:
    """Returns scripted turns regardless of input."""

    def __init__(self, turns: list[AssistantTurn]) -> None:
        self._turns = turns
        self.i = 0

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None) -> AssistantTurn:
        t = self._turns[min(self.i, len(self._turns) - 1)]
        self.i += 1
        return t


def test_agent_loop_runs_tool_then_finishes(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import importlib

    import owlforge.config as config
    importlib.reload(config)
    import owlforge.store.db as db
    importlib.reload(db)
    db.init_db()

    ran = {"probe": False}

    async def _probe(args, ctx):
        ran["probe"] = True
        return "probe-result"

    reg = ToolRegistry()
    reg.add(Tool(name="probe", description="p", parameters={"type": "object", "properties": {}}, run=_probe))

    async def _finish(args, ctx):
        return "done"

    reg.add(
        Tool(name="finish", description="f", parameters={"type": "object", "properties": {}},
             run=_finish, lifecycle=True)
    )

    turns = [
        AssistantTurn(content="let me probe", tool_calls=[ToolCall(id="c1", name="probe", arguments={})]),
        AssistantTurn(content=None, tool_calls=[ToolCall(id="c2", name="finish", arguments={"summary": "all good"})]),
    ]
    emit = Emitter("asmt_test", persist=False)
    summary = asyncio.run(
        run_single_agent(
            client=_FakeClient(turns), registry=reg, emit=emit, assessment_id="asmt_test",
            target="https://example.test", instructions="probe it", scan_mode="quick", max_turns=5,
        )
    )
    assert ran["probe"] is True
    assert summary == "all good"
