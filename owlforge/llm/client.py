"""OpenAI-compatible LLM client.

Works against any local server exposing /v1/chat/completions (Jan, Ollama, LM Studio,
llama.cpp, vLLM) as well as OpenAI itself. Supports two tool-calling strategies:

  * native  — pass `tools=` and read `message.tool_calls`
  * text    — inject a JSON tool protocol into the system prompt and parse it back

`auto` tries native first and, if the server rejects tools or returns none while the
model clearly wanted to act, sticks to text for the rest of the session.
"""

from __future__ import annotations

import json
import time

from owlforge.llm.base import AssistantTurn, LLMClient, Message, ToolCall, ToolSpec
from owlforge.llm.context import trim_messages
from owlforge.llm.toolproto import parse_tool_calls, render_tool_protocol


class LLMError(RuntimeError):
    pass


class OpenAICompatClient(LLMClient):
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        context_window: int = 8192,
        timeout: float = 120.0,
        max_retries: int = 2,
        tool_mode: str = "auto",  # auto | native | text
    ) -> None:
        if not model:
            raise LLMError("No model configured. Set [llm] model in ~/.owlforge/config.toml.")
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise LLMError("The 'openai' package is required (pip install -e .).") from e

        self.model = model
        self.context_window = context_window
        self.timeout = timeout
        self.max_retries = max_retries
        self.tool_mode = tool_mode
        self._client = OpenAI(base_url=base_url, api_key=api_key or "sk-no-auth", timeout=timeout)

    # -- payload helpers -------------------------------------------------
    @staticmethod
    def _to_api(messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            d: dict = {"role": m.role, "content": m.content or ""}
            if m.tool_calls:
                d["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in m.tool_calls
                ]
            if m.role == "tool":
                d["tool_call_id"] = m.tool_call_id or ""
                if m.name:
                    d["name"] = m.name
            out.append(d)
        return out

    @staticmethod
    def _tools_api(tools: list[ToolSpec]) -> list[dict]:
        return [
            {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
            for t in tools
        ]

    def _complete(self, payload: dict) -> object:
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._client.chat.completions.create(**payload)
            except Exception as e:  # transient local-server hiccups
                last = e
                if attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
        raise LLMError(f"LLM request failed after {self.max_retries + 1} tries: {last}")

    # -- main entry ------------------------------------------------------
    def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AssistantTurn:
        tools = tools or []
        max_tokens = max_tokens or 1024
        msgs = trim_messages(messages, self.context_window, reserve_for_output=max_tokens)

        use_native = self.tool_mode in {"auto", "native"} and bool(tools)

        if use_native:
            try:
                return self._chat_native(msgs, tools, temperature, max_tokens)
            except LLMError:
                if self.tool_mode == "native":
                    raise
                self.tool_mode = "text"  # sticky fallback for the rest of the session

        return self._chat_text(msgs, tools, temperature, max_tokens)

    def _chat_native(self, msgs, tools, temperature, max_tokens) -> AssistantTurn:
        payload = {
            "model": self.model,
            "messages": self._to_api(msgs),
            "temperature": temperature if temperature is not None else 0.2,
            "max_tokens": max_tokens,
            "tools": self._tools_api(tools),
            "tool_choice": "auto",
        }
        resp = self._complete(payload)
        choice = resp.choices[0]
        msg = choice.message
        calls: list[ToolCall] = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except Exception:
                args = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
        usage = getattr(resp, "usage", None)
        return AssistantTurn(
            content=msg.content,
            tool_calls=calls,
            finish_reason=choice.finish_reason or "stop",
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )

    def _chat_text(self, msgs, tools, temperature, max_tokens) -> AssistantTurn:
        api_msgs = self._to_api(msgs)
        if tools:
            protocol = render_tool_protocol(tools)
            if api_msgs and api_msgs[0]["role"] == "system":
                api_msgs[0]["content"] = f'{api_msgs[0]["content"]}\n\n{protocol}'
            else:
                api_msgs.insert(0, {"role": "system", "content": protocol})
        payload = {
            "model": self.model,
            "messages": api_msgs,
            "temperature": temperature if temperature is not None else 0.2,
            "max_tokens": max_tokens,
        }
        resp = self._complete(payload)
        choice = resp.choices[0]
        text = choice.message.content or ""
        leftover, calls = parse_tool_calls(text, {t.name for t in tools})
        usage = getattr(resp, "usage", None)
        return AssistantTurn(
            content=leftover,
            tool_calls=calls,
            finish_reason=choice.finish_reason or "stop",
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )


def make_client(cfg) -> OpenAICompatClient:
    return OpenAICompatClient(
        base_url=cfg.llm.base_url,
        api_key=cfg.llm.api_key,
        model=cfg.llm.model,
        context_window=cfg.llm.context_window,
    )
