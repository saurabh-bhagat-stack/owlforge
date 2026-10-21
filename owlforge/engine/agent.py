"""Single-agent think -> act -> observe loop (Phase 1)."""

from __future__ import annotations

import json

from owlforge.engine.events import Emitter
from owlforge.engine.prompts import system_prompt
from owlforge.llm.base import LLMClient, Message
from owlforge.sandbox.client import SandboxClient
from owlforge.tools.base import ToolContext, ToolRegistry

_MAX_TOOL_RESULT = 8000
_DEDUP_TOOLS = {"http_request", "exec_command"}


def _call_sig(name: str, args: dict | None) -> str:
    """Stable signature of a probing call, so identical repeats can be detected."""
    a = args or {}
    if name == "http_request":
        return ("http:" + str(a.get("method", "GET")).upper() + " " + str(a.get("url", ""))
                + " p=" + json.dumps(a.get("params") or {}, sort_keys=True, default=str)
                + " b=" + str(a.get("body") or ""))
    if name == "exec_command":
        return "exec:" + str(a.get("command") or "")
    return ""


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
    session_headers: dict | None = None,
    surface: str | None = None,
    expected_signal: str = "",
) -> str:
    ctx = ToolContext(assessment_id=assessment_id, target=target, emit=emit, sandbox=sandbox,
                      session_headers=session_headers or {})
    messages: list[Message] = [
        Message(role="system", content=system_prompt(target, instructions, scan_mode)),
        Message(role="user", content=(
            f"Assess {target}. {instructions}"
            + (f"\n\n# Attack surface (recon found these — TEST THE PARAMETERS ON EACH)\n{surface}"
               if surface else "")
        )),
    ]
    specs = registry.specs()
    last_summary = ""
    notes: list[str] = []
    actions: list[str] = []
    idle_nudges = 0
    wrapup_sent = False
    call_sigs: dict[str, int] = {}
    last_result_for: dict[str, str] = {}
    findings_created = 0
    finding_nudge_sent = False
    bypass_nudge_sent = False

    for turn in range(1, max_turns + 1):
        emit("status", f"turn {turn}/{max_turns}")
        turn_result = client.chat(messages, specs, temperature=0.2, max_tokens=1024)

        if turn_result.content and turn_result.content.strip():
            emit("assistant", turn_result.content.strip()[:500])

        if not turn_result.tool_calls:
            idle_nudges += 1
            if idle_nudges >= 3:
                emit("log", "no tool call 3x; ending loop")
                break
            messages.append(Message(role="assistant", content=turn_result.content or ""))
            messages.append(Message(role="user", content=(
                "You MUST call a tool to make progress. If you have evidence of a vulnerability "
                "(even partial), call `create_finding` now — include a repro_command and a "
                "success_signal so it can be validated. If a vector was blocked (e.g. escaped), "
                "try a DIFFERENT one (SQLi, path traversal, another parameter/endpoint) with "
                "`exec_command`. If you are genuinely finished, call `finish`. Do not reply with "
                "prose only.")))
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
            sig = _call_sig(call.name, call.arguments)
            if sig and call.name in _DEDUP_TOOLS:
                seen = call_sigs.get(sig, 0)
                call_sigs[sig] = seen + 1
                if seen >= 2:
                    prior = last_result_for.get(sig, "")
                    emit("log", f"blocked duplicate {call.name} (x{seen + 1}) — nudging agent to vary")
                    messages.append(Message(role="tool", tool_call_id=call.id, name=call.name,
                        content=("DUPLICATE REQUEST BLOCKED: you already issued this exact "
                                 f"{call.name} {seen} times and the response did not change"
                                 + (f" (was: {prior[:160]})" if prior else "")
                                 + ". Do NOT repeat it. Change the parameter or payload, test a "
                                 "DIFFERENT endpoint/parameter from the surface, or — if you already "
                                 "have evidence — call create_finding. If genuinely done, call finish.")))
                    continue
            try:
                result = await tool.run(call.arguments, ctx)
            except Exception as e:  # a tool crash must not kill the loop
                result = f"tool error: {type(e).__name__}: {e}"
            if sig:
                last_result_for[sig] = result
            if call.name == "create_finding" and "filed as candidate" in result:
                findings_created += 1
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
            if findings_created == 0 and not bypass_nudge_sent and expected_signal:
                bypass_nudge_sent = True
                from owlforge.engine.ledger import attempts_summary
                tried = attempts_summary(assessment_id, limit=15)
                emit("log", "finishing with 0 findings despite a pre-probe signal — pushing bypass attempts")
                messages.append(Message(role="user", content=(
                    f"A deterministic pre-probe ALREADY confirmed a live signal here: {expected_signal}. "
                    "You filed 0 findings, so do NOT give up — the vector is live, you just have not landed "
                    "it. Try BYPASS techniques before finishing: URL- and double-URL-encoding, HTML-entity / "
                    "unicode escaping, a different injection context (HTML tag vs attribute vs JS string vs "
                    "URL), case / comment / whitespace variation, and alternate parameters or HTTP methods. "
                    "Use exec_command with the sandbox tools if http_request is being filtered. "
                    + (f"Payloads already tried (do NOT repeat these):\n{tried}\n" if tried else "")
                    + "When one works, call create_finding with the exact payload; only finish if you have "
                    "genuinely exhausted these.")))
                continue
            if (findings_created == 0 and not finding_nudge_sent
                    and _claims_unfiled_vuln(notes, last_summary)):
                finding_nudge_sent = True
                emit("log", "finish called with 0 findings but a vulnerability was "
                            "described — requiring create_finding before finishing")
                messages.append(Message(role="user", content=(
                    "You called `finish` but filed 0 findings, while your notes describe a "
                    "confirmed vulnerability. A note or a finish summary is NOT a finding and "
                    "will be discarded. Call `create_finding` NOW for each vulnerability you "
                    "confirmed, with the structured repro fields: title, severity, repro_url, "
                    "repro_method, repro_params, and success_signal (the exact observation that "
                    "proves it, e.g. \"status 500 on category=' while category='' returns 200\"). "
                    "If on reflection nothing is actually confirmed, call `finish` again.")))
                continue
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


_VULN_CLAIM = ("confirmed", "is vulnerable", "injection on", "exploitable",
               "successfully inject", "able to inject", "vulnerability confirmed",
               "is exploitable", "proven")
_VULN_NEG = ("not confirmed", "unconfirmed", "not vulnerable", "not exploitable",
             "no vulnerab", "could not confirm", "unable to confirm")


def _claims_unfiled_vuln(notes: list[str], summary: str) -> bool:
    """Did the agent describe a confirmed vulnerability in its notes/summary? If so, a
    bare `finish` with zero findings is almost certainly a missed create_finding call
    (the harness nudges it once to file one — robustness for weaker drivers)."""
    blob = (" ".join(notes) + " " + (summary or "")).lower()
    if not blob.strip():
        return False
    for neg in _VULN_NEG:
        blob = blob.replace(neg, " ")
    return any(p in blob for p in _VULN_CLAIM)


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
