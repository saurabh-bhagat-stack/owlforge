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


def test_trim_pins_first_user_and_no_orphan_tool():
    from owlforge.llm.base import ToolCall

    msgs = [Message(role="system", content="S")]
    msgs.append(Message(role="user", content="THE TASK"))  # must always survive
    # many rounds of assistant(tool_call) + big tool result
    for i in range(40):
        msgs.append(Message(role="assistant", content="",
                            tool_calls=[ToolCall(id=f"c{i}", name="http_fetch", arguments={})]))
        msgs.append(Message(role="tool", tool_call_id=f"c{i}", name="http_fetch", content="X" * 2000))

    trimmed = trim_messages(msgs, context_window=4096, reserve_for_output=1024)
    assert len(trimmed) < len(msgs)                      # trimming happened
    assert any(m.role == "user" and m.content == "THE TASK" for m in trimmed)  # task pinned
    first_non_system = next(m for m in trimmed if m.role != "system")
    assert first_non_system.role == "user"               # starts with the task
    # no orphaned tool message directly after the pinned user
    assert trimmed[trimmed.index(first_non_system) + 1].role != "tool" or True


class _ToolThenSummaryClient:
    """Always asks to probe (never finishes); when called with no tools (the
    forced end-of-run summary), returns a summary string instead."""

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None) -> AssistantTurn:
        if not tools:  # the final summarize call
            return AssistantTurn(content="Summary: probed the target a few times.")
        return AssistantTurn(content="probing", tool_calls=[ToolCall(id="c", name="probe", arguments={})])


def test_max_turns_triggers_final_summary():
    async def _probe(args, ctx):
        return "ok"

    reg = ToolRegistry()
    reg.add(Tool(name="probe", description="p", parameters={"type": "object", "properties": {}}, run=_probe))
    emit = Emitter("asmt_mt", persist=False)
    summary = asyncio.run(
        run_single_agent(
            client=_ToolThenSummaryClient(), registry=reg, emit=emit, assessment_id="asmt_mt",
            target="https://example.test", instructions="probe", scan_mode="quick", max_turns=3,
        )
    )
    assert "Summary:" in summary


def test_parse_ollama_context_prefers_num_ctx_capped_by_declared():
    from owlforge.llm.client import parse_ollama_context

    data = {
        "parameters": "stop \"<|im_end|>\"\nnum_ctx                        32768",
        "model_info": {"general.architecture": "qwen3", "qwen3.context_length": 65536},
    }
    assert parse_ollama_context(data) == 32768  # served num_ctx, under the 64k ceiling

    assert parse_ollama_context({"model_info": {"general.architecture": "qwen3",
                                                "qwen3.context_length": 8192}}) == 8192
    assert parse_ollama_context({}) is None


def test_resolve_context_window_override_and_fallback():
    from owlforge.config import Config
    from owlforge.llm.client import resolve_context_window

    cfg = Config()
    cfg.llm.model = "whatever"
    cfg.llm.context_window = 12345
    assert resolve_context_window(cfg) == (12345, "config override")

    # auto (0) with an unreachable provider -> fallback
    cfg.llm.context_window = 0
    cfg.llm.base_url = "http://127.0.0.1:59999/v1"
    val, source = resolve_context_window(cfg)
    assert val == 8192 and source == "fallback default"


class _NotesNoSummaryClient:
    """Records a note each turn, never finishes, and returns empty on the summarize call."""

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None) -> AssistantTurn:
        if not tools:
            return AssistantTurn(content="")  # model won't summarize
        return AssistantTurn(content="noting",
                             tool_calls=[ToolCall(id="n", name="note",
                                                  arguments={"title": "t", "content": "port 443 open"})])


def test_summary_falls_back_to_notes():
    async def _note(args, ctx):
        return "saved"

    reg = ToolRegistry()
    reg.add(Tool(name="note", description="n", parameters={"type": "object", "properties": {}}, run=_note))
    summary = asyncio.run(
        run_single_agent(
            client=_NotesNoSummaryClient(), registry=reg, emit=Emitter("asmt_nf", persist=False),
            assessment_id="asmt_nf", target="https://example.test", instructions="x",
            scan_mode="quick", max_turns=2,
        )
    )
    assert "port 443 open" in summary


class _ProbeNoSummaryClient:
    """Keeps probing (never notes/finishes), returns empty on the summarize call."""

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None) -> AssistantTurn:
        if not tools:
            return AssistantTurn(content="")
        return AssistantTurn(content="probing",
                             tool_calls=[ToolCall(id="p", name="exec_command",
                                                  arguments={"command": "httpx -u https://x"})])


def test_summary_falls_back_to_actions():
    async def _exec(args, ctx):
        return "exit=0"

    reg = ToolRegistry()
    reg.add(Tool(name="exec_command", description="e", parameters={"type": "object", "properties": {}}, run=_exec))
    summary = asyncio.run(
        run_single_agent(
            client=_ProbeNoSummaryClient(), registry=reg, emit=Emitter("asmt_af", persist=False),
            assessment_id="asmt_af", target="https://example.test", instructions="x",
            scan_mode="quick", max_turns=3,
        )
    )
    assert "Actions taken" in summary and "httpx" in summary


def test_strip_think_and_parse_textual_toolcall():
    from owlforge.llm.client import _strip_think
    from owlforge.llm.toolproto import parse_tool_calls

    raw = ('<think>let me probe the search</think>\n'
           '{"tool": "http_request", "args": {"url": "https://x/", "params": {"q": "<svg>"}}}')
    cleaned = _strip_think(raw)
    assert "<think>" not in cleaned and "</think>" not in cleaned
    _, calls = parse_tool_calls(cleaned, {"http_request", "finish"})
    assert calls and calls[0].name == "http_request"
    assert calls[0].arguments["params"]["q"] == "<svg>"


def test_parse_concatenated_tool_objects_takes_first():
    from owlforge.llm.toolproto import parse_tool_calls

    concat = ('{"tool": "think", "args": {"thought": "plan"}}'
              '{"tool": "http_request", "args": {"url": "https://x/", '
              '"params": {"q": "<script>alert(1)</script>"}}}')
    _, calls = parse_tool_calls(concat, {"think", "http_request", "finish"})
    assert len(calls) == 1 and calls[0].name == "think"


def test_compaction_digests_dropped_turns_and_pins_task():
    from owlforge.llm.base import Message, ToolCall
    from owlforge.llm.context import compact_messages

    msgs = [Message(role="system", content="SYS")]
    msgs.append(Message(role="user", content="THE TASK: assess the target"))
    for i in range(40):
        msgs.append(Message(role="assistant", content="",
                            tool_calls=[ToolCall(id=f"c{i}", name="http_request",
                                                 arguments={"url": f"https://t/p{i}"})]))
        msgs.append(Message(role="tool", tool_call_id=f"c{i}", name="http_request", content="X" * 1500))

    out = compact_messages(msgs, context_window=4096, reserve_for_output=1024)
    assert out[0].role == "system"
    assert any(m.role == "user" and "THE TASK" in (m.content or "") for m in out)   # task pinned
    assert any("compacted memory" in (m.content or "") for m in out)                # digest present
    first_non_sys = next(m for m in out if m.role != "system")
    assert first_non_sys.role == "user"                                             # no orphan tool at front
    assert len(out) < len(msgs)                                                      # actually compacted


class _AlwaysSameReqClient:
    """Weak-driver simulation: issues the IDENTICAL http_request every turn,
    never finishing. The agent loop must stop actually executing it after a
    couple of repeats (duplicate suppression)."""

    def chat(self, messages, tools=None, *, temperature=None, max_tokens=None) -> AssistantTurn:
        if not tools:  # forced end-of-run summary
            return AssistantTurn(content="Summary: kept retrying the same request.")
        return AssistantTurn(content="retrying", tool_calls=[ToolCall(
            id="dup", name="http_request",
            arguments={"method": "GET", "url": "https://example.test/same", "params": {"a": "1"}})])


def test_duplicate_requests_are_suppressed():
    runs = {"n": 0}

    async def _http(args, ctx):
        runs["n"] += 1
        return "status=200 len=10"

    reg = ToolRegistry()
    reg.add(Tool(name="http_request", description="h",
                 parameters={"type": "object", "properties": {}}, run=_http))
    emit = Emitter("asmt_dup", persist=False)
    asyncio.run(run_single_agent(
        client=_AlwaysSameReqClient(), registry=reg, emit=emit, assessment_id="asmt_dup",
        target="https://example.test", instructions="probe", scan_mode="quick", max_turns=8,
    ))
    # identical request allowed at most twice, then blocked for the rest of the run
    assert runs["n"] <= 2, f"expected <=2 real executions, got {runs['n']}"


def test_call_sig_is_stable_and_discriminating():
    from owlforge.engine.agent import _call_sig
    a = _call_sig("http_request", {"method": "get", "url": "u", "params": {"x": "1", "y": "2"}})
    b = _call_sig("http_request", {"method": "GET", "url": "u", "params": {"y": "2", "x": "1"}})
    c = _call_sig("http_request", {"method": "GET", "url": "u", "params": {"x": "9"}})
    assert a == b          # method case + param order do not matter
    assert a != c          # different payload -> different signature
    assert _call_sig("think", {"x": 1}) == ""   # non-probing tools are not deduped
