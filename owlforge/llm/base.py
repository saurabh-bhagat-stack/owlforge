"""Core LLM types + the client protocol the engine depends on.

The engine never talks to a provider SDK directly — it talks to an ``LLMClient``.
Phase 1 ships one implementation (OpenAI-compatible, covering every local server:
Jan / Ollama / LM Studio / llama.cpp). A LiteLLM-backed client can be added behind
the same interface later for hosted multi-provider use without touching callers.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Role = Literal["system", "user", "assistant", "tool"]


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Message(BaseModel):
    role: Role
    content: str | None = None
    # assistant messages that triggered tools:
    tool_calls: list[ToolCall] = Field(default_factory=list)
    # tool-result messages:
    tool_call_id: str | None = None
    name: str | None = None


class ToolSpec(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema


class AssistantTurn(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    finish_reason: str = "stop"
    prompt_tokens: int = 0
    completion_tokens: int = 0


@runtime_checkable
class LLMClient(Protocol):
    def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AssistantTurn: ...
