"""Text tool-call protocol — the fallback for local models/servers that don't do
native OpenAI function-calling reliably.

We instruct the model to emit exactly one JSON object describing its tool call, then
parse it back out robustly (fenced ```json block, a bare object, or the first {...}).
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from owlforge.llm.base import ToolCall, ToolSpec


def render_tool_protocol(tools: list[ToolSpec]) -> str:
    lines = [
        "# TOOL PROTOCOL",
        "You act by calling tools. To call one, emit a SINGLE JSON object and nothing else:",
        '    {"tool": "<name>", "args": { ... }}',
        "Call exactly one tool per turn. No prose outside the JSON.",
        "",
        "Available tools:",
    ]
    for t in tools:
        props = (t.parameters or {}).get("properties", {})
        arglist = ", ".join(props.keys()) if props else "(none)"
        lines.append(f'- {t.name}({arglist}): {t.description}')
    return "\n".join(lines)


def _coerce(obj: Any, tool_names: set[str]) -> ToolCall | None:
    if not isinstance(obj, dict):
        return None
    # explicit form: {"tool": "...", "args": {...}}
    name = obj.get("tool") or obj.get("name")
    args = obj.get("args")
    if isinstance(name, str) and name in tool_names:
        if not isinstance(args, dict):
            args = {k: v for k, v in obj.items() if k not in {"tool", "name", "args"}}
        return ToolCall(id=f"call_{secrets.token_hex(4)}", name=name, arguments=args or {})
    return None


def _try_json(raw: str) -> Any | None:
    try:
        return json.loads(raw)
    except Exception:
        return None


def _iter_json_objects(text: str):
    """Yield (start_index, substring) for each top-level balanced {...} object.

    Handles models that concatenate several JSON tool-call objects in one response
    (and trailing junk) — a plain first-brace/last-brace slice would be invalid JSON.
    """
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_str = False
        esc = False
        for j in range(i, n):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield i, text[i : j + 1]
                    break
        else:
            return  # unbalanced tail; nothing more to find
        i = j + 1


def parse_tool_calls(text: str, tool_names: set[str]) -> tuple[str | None, list[ToolCall]]:
    """Return (leftover_prose, tool_calls). At most one tool call is extracted."""
    if not text:
        return None, []

    # 1) fenced ```json ... ``` blocks
    import re

    for m in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", text):
        tc = _coerce(_try_json(m.group(1).strip()), tool_names)
        if tc:
            leftover = (text[: m.start()] + text[m.end():]).strip()
            return (leftover or None), [tc]

    # 2) whole string is a JSON object
    tc = _coerce(_try_json(text.strip()), tool_names)
    if tc:
        return None, [tc]

    # 3. Scan for the FIRST balanced {...} object that coerces to a tool call
    #    (models may concatenate several objects, or append prose/junk).
    for start, obj in _iter_json_objects(text):
        tc = _coerce(_try_json(obj), tool_names)
        if tc:
            return (text[:start].strip() or None), [tc]

    return (text.strip() or None), []
