"""Single-agent think -> act -> observe loop (Phase 1)."""

from __future__ import annotations

from owlforge.engine.events import Emitter
from owlforge.engine.prompts import system_prompt
from owlforge.llm.base import LLMClient, Message
from owlforge.sandbox.client import SandboxClient
from owlforge.tools.base import ToolContext, ToolRegistry

_MAX_TOOL_RESULT = 8000


async def run_single_agent(
    *,
    client: LLMClient,
    registry: ToolRegistry,
    emit: Emitter,
    assessment_id: str,
    target: str,
    instructions: str,
    scan_mode: str,
    max_turns: int = 20,
    sandbox: SandboxClient | None = None,
) -> str:
    ctx = ToolContext(assessment_id=assessment_id, target=target, emit=emit, sandbox=sandbox)
    messages: list[Message] = [
        Message(role="system", content=system_prompt(target, instructions, scan_mode)),
        Message(role="user", content=f"Assess {target}. {instructions}"),
    ]
    specs = registry.specs()
    last_summary = ""
    notes: list[str] = []
    actions: list[str] = []
    idle_nudges = 0
    wrapup_sent = False

    for turn in range(1, max_turns + 1):
        emit("status", f"turn {turn}/{max_turns}")
        turn_result = client.chat(messages, specs, temperature=0.2, max_tokens=1024)

        if turn_result.content and turn_result.content.strip():
            emit("assistant", turn_result.content.strip()[:500])

        if not turn_result.tool_calls:
            idle_nudges += 1
            if idle_nudges >= 2:
                emit("log", "no tool call twice; ending loop")
                break
            messages.append(Message(role="assistant", content=turn_result.content or ""))
            messages.append(Message(role="user", content=(
                "You did not call a tool. Call `think`, `http_fetch`, `note`, or `finish`.")))
            continue
        idle_nudges = 0

        # record the assistant turn (with its tool calls) before the tool results
        messages.append(Message(role="assistant", content=turn_result.content or "", tool_calls=turn_result.tool_calls))

        lifecycle = False
        for call in turn_result.tool_calls:
            tool = registry.get(call.name)
            if not tool:
                messages.append(Message(role="tool", tool_call_id=call.id, name=call.name,
                                        content=f"Unknown tool {call.name}."))
                continue
            try:
                result = await tool.run(call.arguments, ctx)
            except Exception as e:  # a tool crash must not kill the loop
                result = f"tool error: {type(e).__name__}: {e}"
            if tool.name not in {"think", "finish"}:
                emit("tool_result", f"{tool.name} -> {result[:200]}")
            messages.append(Message(role="tool", tool_call_id=call.id, name=call.name,
                                    content=result[:_MAX_TOOL_RESULT]))
            if call.name == "note":
                notes.append(str(call.arguments.get("content") or call.arguments.get("title") or "").strip())
            elif call.name not in {"think", "finish"}:
                _arg = str(call.arguments.get("command") or call.arguments.get("url")
                           or call.arguments.get("query") or "").strip()
                actions.append(f"{call.name}: {_arg[:100]}" if _arg else call.name)
            if tool.lifecycle:
                lifecycle = True
                last_summary = str(call.arguments.get("summary", "")).strip()

        if lifecycle:
            emit("status", "assessment finished by agent")
            return _finalize(last_summary, notes, actions, emit)

        if turn >= max_turns - 2 and not wrapup_sent:
            wrapup_sent = True
            emit("log", "turn budget low — nudging agent to record findings and finish")
            messages.append(Message(role="user", content=(
                "You are almost out of turns. Stop probing now. Call `note` once per concrete "
                "finding you have evidence for, then call `finish` with a summary.")))

    emit("status", "max turns reached — requesting final summary")
    try:
        messages.append(Message(role="user", content=(
            "You have reached your step budget. Do NOT call any tools. Write a concise "
            "summary of what you examined and what you found.")))
        final = client.chat(messages, [], temperature=0.2, max_tokens=512)
        if final.content and final.content.strip():
            last_summary = final.content.strip()
    except Exception as e:  # summary is best-effort
        emit("log", f"summary generation failed: {type(e).__name__}: {e}")
    return _finalize(last_summary, notes, actions, emit)


def _finalize(summary: str, notes: list[str], actions: list[str], emit: Emitter) -> str:
    """Always yield a usable summary: the model's, else a digest of its notes,
    else a digest of the actions it actually took (so a run is never empty)."""
    summary = (summary or "").strip()
    if not summary and notes:
        kept = [n for n in notes if n]
        summary = "Summary assembled from recorded notes:\n- " + "\n- ".join(kept)
    if not summary and actions:
        summary = ("No explicit summary or notes were recorded. Actions taken:\n- "
                   + "\n- ".join(actions[-25:]))
    summary = summary or "No summary produced (the agent took no actions)."
    emit("finish", summary[:2000])
    return summary
