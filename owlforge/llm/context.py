"""Token-aware history trimming so missions don't overflow a small local context.

Phase 1 uses a cheap chars/4 token estimate (good enough for trimming decisions);
a tiktoken-based estimate can drop in later behind ``estimate_tokens``.
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
    """Always keep system messages + the latest user/task; drop the OLDEST
    non-system messages until the estimate fits (context_window - reserve)."""
    budget = max(512, context_window - reserve_for_output)
    system = [m for m in messages if m.role == "system"]
    rest = [m for m in messages if m.role != "system"]

    used = sum(message_tokens(m) for m in system)
    kept: list[Message] = []
    # walk newest -> oldest, keep while under budget
    for m in reversed(rest):
        cost = message_tokens(m)
        if used + cost > budget and kept:
            break
        used += cost
        kept.append(m)
    kept.reverse()
    return system + kept
