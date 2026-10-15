"""Load the playbook catalog (editable YAML) and render it for prompts.

The catalog is DATA, not code — add/edit YAML under knowledge/playbooks/ to extend
owlforge's methodology without touching the engine. Ordered by `priority`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_DIR = Path(__file__).parent / "playbooks"


@lru_cache(maxsize=1)
def load_playbooks() -> list[dict]:
    skills: list[dict] = []
    for f in sorted(_DIR.glob("*.yaml")):
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and d.get("name"):
            skills.append(d)
    skills.sort(key=lambda s: s.get("priority", 10))
    return skills


def render_playbooks(names: list[str] | None = None) -> str:
    skills = load_playbooks()
    if names:
        wanted = set(names)
        skills = [s for s in skills if s["name"] in wanted]
    blocks = [f"## {s.get('title', s['name'])}\n{str(s.get('body', '')).strip()}" for s in skills]
    return "\n\n".join(blocks)
