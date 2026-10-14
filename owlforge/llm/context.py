"""Token-aware history trimming so missions don't overflow a small local context.

Phase 1 uses a cheap chars/4 token estimate (good enough for trimming decisions);
a tiktoken-based estimate can drop in later behind ``estimate_tokens``.

Two invariants the trimmer MUST preserve, learned from a live Qwen3-template crash:
  1. Always keep the first user message (the task). Chat templates (Qwen3 et al.)
     raise "No user query found in messages." if no plain user turn survives.
  2. Never leave an orphaned `tool` message at the front of the kept tail — a tool
     result whose assistant tool-call parent was trimmed away. OpenAI-compatible
     servers reject a tool message with no preceding assistant tool_call.
"""

from __future__ import annotations

from owlforge.llm.base import Message


def estimate_tokens(text: str | None) -> int:
    if not text:
        return 0
    return max(1, len(text) // 4)


def message_tokens(m: Message) -> int:
    total = estimate_tokens(m.content)
    for tc in m.tool_calls:
        total += estimate_tokens(tc.name) + estimate_tokens(str(tc.arguments))
    return total + 4  # per-message overhead


def trim_messages(
    messages: list[Message],
    context_window: int,
    reserve_for_output: int,
) -> list[Message]:
    """Keep system messages + the first user message (task) + the newest tail that
    fits in (context_window - reserve_for_output). Oldest middle messages are dropped."""
    budget = max(512, context_window - reserve_for_output)
    system = [m for m in messages if m.role == "system"]
    non_system = [m for m in messages if m.role != "system"]

    # Pin the first user message so a plain user query always survives.
    first_user_idx = next((i for i, m in enumerate(non_system) if m.role == "user"), None)
    if first_user_idx is not None:
        pinned = [non_system[first_user_idx]]
        tail_pool = non_system[first_user_idx + 1 :]
    else:
        pinned = []
        tail_pool = non_system

    used = sum(message_tokens(m) for m in system) + sum(message_tokens(m) for m in pinned)
    kept: list[Message] = []
    for m in reversed(tail_pool):
        cost = message_tokens(m)
        if used + cost > budget and kept:
            break
        used += cost
        kept.append(m)
    kept.reverse()

    # Drop leading orphaned tool results (their assistant parent was trimmed out).
    while kept and kept[0].role == "tool":
        kept.pop(0)

    return system + pinned + kept
