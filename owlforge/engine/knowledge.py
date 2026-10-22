"""Knowledge packs — methodology injected into a specialist's prompt at dispatch.

A pack is `owlforge/knowledge/<category>/<name>.md` with YAML frontmatter (`name`,
`applies_to`, `description`) followed by a methodology body (techniques, bypasses,
validation signals, example payloads). Selection is deterministic and budget-capped so
weak local models are not drowned:

  * the specialist's CLASS pack always loads (e.g. the SQLi specialist gets vuln/sqli.md);
  * FRAMEWORK/TECH packs load when recon fingerprinted that stack (Django, Express, …);
  * at most `max_packs` packs and `max_chars` characters are injected.

User-authored packs can live under `knowledge/custom/` or a directory named in config;
nothing here is tied to a specific target. Pure stdlib + PyYAML; no network, no model.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent / "knowledge"

# class value (owlforge.engine.classify) -> pack path, relative to the knowledge root
_CLASS_PACK = {
    "sqli": "vuln/sqli.md",
    "xss": "vuln/xss.md",
    "path_traversal": "vuln/path_traversal.md",
    "access_control": "vuln/access_control.md",
    "ssrf_redirect": "vuln/ssrf_redirect.md",
    "csrf": "vuln/csrf.md",
    "ssti": "vuln/ssti.md",
    "rce": "vuln/rce.md",
    "open_redirect": "vuln/open_redirect.md",
    "xxe": "vuln/xxe.md",
    "nosql": "vuln/nosql.md",
    "file_upload": "vuln/file_upload.md",
    "deserialization": "vuln/deserialization.md",
    "graphql": "protocol/graphql.md",
}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _parse(path: Path) -> tuple[dict, str]:
    """Return (frontmatter dict, body) for a pack file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except Exception:
                meta = {}
            return (meta if isinstance(meta, dict) else {}), parts[2].strip()
    return {}, text.strip()


def _read_body(rel: str, root: Path | None = None) -> str:
    p = (root or _ROOT) / rel
    if not p.is_file():
        return ""
    try:
        _, body = _parse(p)
        return body
    except Exception:
        return ""


def select_knowledge(cls: str, tech: list[str] | None = None, inventory=None, *,
                     max_packs: int = 4, max_chars: int = 6000,
                     extra_root: Path | None = None) -> str:
    """Pick and concatenate the packs relevant to this specialist. Returns a prompt
    fragment (headed '# applied knowledge'), or '' when nothing matched."""
    chosen: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(rel: str) -> None:
        if rel in seen or len(chosen) >= max_packs:
            return
        body = _read_body(rel)
        if not body and extra_root is not None:
            body = _read_body(rel, extra_root)
        if body:
            chosen.append((rel, body))
            seen.add(rel)

    cls_rel = _CLASS_PACK.get(cls)
    if cls_rel:
        _add(cls_rel)
    for t in (tech or []):
        s = _slug(t)
        if not s:
            continue
        for rel in (f"framework/{s}.md", f"tech/{s}.md"):
            _add(rel)

    out, total = [], 0
    for _rel, body in chosen[:max_packs]:
        if out and total + len(body) > max_chars:
            break
        out.append(body)
        total += len(body)
    if not out:
        return ""
    return ("\n\n# Applied knowledge (methodology packs — use these techniques and "
            "validation signals)\n\n" + "\n\n---\n\n".join(out))


def available_packs(root: Path | None = None) -> list[str]:
    """List pack paths relative to the knowledge root (for diagnostics/tests)."""
    base = root or _ROOT
    if not base.is_dir():
        return []
    return sorted(str(p.relative_to(base)) for p in base.rglob("*.md"))
