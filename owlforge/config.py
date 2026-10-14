"""owlforge configuration.

Loads from ``$OWLFORGE_HOME/config.toml`` (default ``~/.owlforge``). Falls back to
sane local-first defaults so the tool runs out of the box. The same directory holds
the SQLite store and per-assessment workspaces.
"""

from __future__ import annotations

import os
import tomllib
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    # Any OpenAI-compatible endpoint. Default = Jan's local server.
    base_url: str = "http://127.0.0.1:1337/v1"
    api_key: str = ""
    model: str = ""  # operator sets this to their local model id
    temperature: float = 0.2
    max_tokens: int = 4096
    # History-trimming budget. 0 = auto-detect from the provider (Ollama /api/show);
    # >0 = explicit override (use when the served context is smaller than detected).
    context_window: int = 0
    # Before a run, offload any OTHER models the local provider has in memory (Ollama).
    # Handy on limited RAM + for model benchmarking (one model resident at a time).
    free_other_models: bool = False


class SandboxConfig(BaseModel):
    enabled: bool = True
    image: str = "ghcr.io/saurabh-bhagat-stack/owlforge-sandbox:dev"
    # Daemon port published to 127.0.0.1 on the host (Phase 2).
    agentd_port: int = 47130


class RunnerConfig(BaseModel):
    max_turns: int = 40
    max_budget_usd: float = 0.0  # 0 = unlimited (local models are free)
    reasoning_effort: str = "medium"


class TestingConfig(BaseModel):
    default_target: str = "https://ginandjuice.shop/"


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    runner: RunnerConfig = Field(default_factory=RunnerConfig)
    testing: TestingConfig = Field(default_factory=TestingConfig)


def owlforge_home() -> Path:
    return Path(os.environ.get("OWLFORGE_HOME", Path.home() / ".owlforge"))


def config_path() -> Path:
    return owlforge_home() / "config.toml"


def db_path() -> Path:
    return owlforge_home() / "owlforge.db"


def assessments_dir() -> Path:
    return owlforge_home() / "assessments"


@lru_cache(maxsize=1)
def load_config() -> Config:
    path = config_path()
    if path.exists():
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        return Config.model_validate(data)
    return Config()


DEFAULT_CONFIG_TOML = """\
# owlforge config. Point `model` at a model your local server actually serves.
[llm]
base_url = "http://127.0.0.1:1337/v1"
api_key = ""
model = ""
temperature = 0.2
max_tokens = 4096
context_window = 0   # 0 = auto-detect from the model
free_other_models = false   # true = offload other Ollama models before a run (saves RAM; good for benchmarking)

[sandbox]
enabled = true
image = "ghcr.io/saurabh-bhagat-stack/owlforge-sandbox:dev"
agentd_port = 47130

[runner]
max_turns = 40
max_budget_usd = 0.0
reasoning_effort = "medium"

[testing]
default_target = "https://ginandjuice.shop/"
"""


def write_default_config(force: bool = False) -> Path:
    home = owlforge_home()
    home.mkdir(parents=True, exist_ok=True)
    assessments_dir().mkdir(parents=True, exist_ok=True)
    path = config_path()
    if path.exists() and not force:
        return path
    path.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
    load_config.cache_clear()
    return path
