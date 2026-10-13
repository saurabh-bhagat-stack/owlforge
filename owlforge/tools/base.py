"""Tool registry + context. A Tool is a typed, named capability the agent can call."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from owlforge.llm.base import ToolSpec


@dataclass
class ToolContext:
    assessment_id: str
    target: str
    emit: Callable[..., None]
    # Phase 2 will add a sandbox RPC client here; Phase 1 tools run engine-side.


ToolFn = Callable[[dict[str, Any], ToolContext], Awaitable[str]]


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    run: ToolFn
    lifecycle: bool = False  # true = ends the agent loop (e.g. finish)

    def spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.description, parameters=self.parameters)


@dataclass
class ToolRegistry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def add(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self.tools.get(name)

    def specs(self) -> list[ToolSpec]:
        return [t.spec() for t in self.tools.values()]

    def names(self) -> set[str]:
        return set(self.tools)
