"""Knowledge-pack loader: selection, fingerprint matching, budget."""
from __future__ import annotations

from owlforge.engine.knowledge import available_packs, select_knowledge


def test_packs_present():
    packs = available_packs()
    assert len(packs) >= 12
    assert "vuln/sqli.md" in packs and "protocol/graphql.md" in packs


def test_class_pack_always_loads():
    k = select_knowledge("sqli", [])
    assert "ORDER BY probing" in k            # sqli body
    assert "Applied knowledge" in k


def test_fingerprint_adds_framework_packs():
    k = select_knowledge("sqli", ["Django", "React"])
    assert "ORDER BY probing" in k            # class pack
    assert "DisallowedHost" in k              # Django pack
    assert "dangerouslySetInnerHTML" in k     # React pack


def test_graphql_class_maps_to_protocol_pack():
    k = select_knowledge("graphql", [])
    assert "introspection" in k.lower()


def test_budget_caps_pack_count():
    k = select_knowledge("sqli", ["Django", "React", "Express"], max_packs=2)
    assert "DisallowedHost" in k              # class + first framework
    assert "dangerouslySetInnerHTML" not in k  # capped out


def test_unknown_class_without_tech_is_empty():
    assert select_knowledge("totally_unknown", []) == ""


def test_tech_slug_is_tolerant():
    # "Next.js" -> nextjs pack
    k = select_knowledge("xss", ["Next.js"])
    assert "_next" in k.lower()
