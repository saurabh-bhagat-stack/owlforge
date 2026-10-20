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
    default_target: str = ""  # operator supplies the target with --target


class OastConfig(BaseModel):
    """Out-of-band application security testing (blind SSRF/XXE/RCE/SQLi callbacks).

    Resolution order when enabled: (1) public interactsh `server`; (2) a cloudflared (or
    ngrok) tunnel to an in-sandbox listener; (3) a bring-your-own collaborator
    (`collaborator_url` [+ `token`], a self-hosted interactsh); else owlforge flags
    affected sinks "needs manual verification" and tells you to configure one."""
    enabled: bool = True
    collaborator_url: str = ""  # BYO self-hosted interactsh / collaborator domain (tried first)
    token: str = ""             # auth token for a protected self-hosted server
    server: str = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"  # public interactsh
    tunnel: bool = True         # if interactsh is blocked, expose a sandbox listener via cloudflared
    ngrok_token: str = ""       # optional: use ngrok instead of cloudflared (needs an authtoken)
    wait_seconds: int = 12      # how long to wait for callbacks after injecting


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    runner: RunnerConfig = Field(default_factory=RunnerConfig)
    testing: TestingConfig = Field(default_factory=TestingConfig)
    oast: OastConfig = Field(default_factory=OastConfig)


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

[sandbox]
enabled = true
image = "ghcr.io/saurabh-bhagat-stack/owlforge-sandbox:dev"
agentd_port = 47130

[runner]
max_turns = 40
max_budget_usd = 0.0
reasoning_effort = "medium"

[oast]
# Out-of-band testing for blind SSRF/XXE. Order: public interactsh -> cloudflared/ngrok
# tunnel -> your configured collaborator_url. If all are blocked, affected sinks are
# flagged "needs manual verification" and owlforge tells you to set collaborator_url here.
enabled = true
collaborator_url = ""   # e.g. your self-hosted interactsh domain (tried first)
token = ""              # auth token for a protected self-hosted server
server = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"
tunnel = true           # if interactsh is blocked, tunnel a sandbox listener via cloudflared
ngrok_token = ""        # optional: use ngrok instead of cloudflared (needs an authtoken)
wait_seconds = 12

[testing]
default_target = ""  # set your authorized target, or pass --target
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
