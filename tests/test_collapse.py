"""Passive-finding site-wide collapse."""
from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _seed(db):
    from owlforge.store.models import Finding
    with db.session() as s:
        # same passive issue across 3 endpoints + a distinct passive issue + a real finding
        for i, ep in enumerate(["/", "/catalog", "/blog"]):
            s.add(Finding(id=f"csp{i}", assessment_id="a", title="Missing Content-Security-Policy",
                          severity="low", status="candidate", endpoint=ep,
                          validation_note="passive observation (deterministic)"))
        s.add(Finding(id="hsts0", assessment_id="a", title="Missing HSTS", severity="low",
                      status="candidate", endpoint="/", validation_note="passive observation (deterministic)"))
        s.add(Finding(id="sqli0", assessment_id="a", title="SQL injection", severity="high",
                      status="validated", endpoint="/catalog", validation_note="reproduced"))
        s.commit()


def test_collapse_merges_same_title_passive(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from sqlmodel import select

    from owlforge.engine.validate import collapse_passive_findings
    from owlforge.store.models import Finding
    n = collapse_passive_findings("a")
    assert n == 2  # two of the three CSP rows collapsed
    with db.session() as s:
        rows = {f.id: f for f in s.exec(select(Finding).where(Finding.assessment_id == "a")).all()}
    csp_live = [f for f in rows.values() if f.title == "Missing Content-Security-Policy"
                and f.status == "candidate"]
    assert len(csp_live) == 1
    kept = csp_live[0]
    assert "site-wide" in kept.endpoint and "Affected endpoints (3)" in kept.technical_analysis
    assert rows["hsts0"].status == "candidate"   # distinct passive issue untouched
    assert rows["sqli0"].status == "validated"   # real finding untouched


def test_validation_preserves_passive_marker_so_collapse_still_works(tmp_path, monkeypatch):
    """Regression: the no-repro validation branch used to overwrite the
    "passive observation" note, orphaning per-endpoint config findings so the
    site-wide collapse could no longer group them (inflated the report)."""
    import asyncio

    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from sqlmodel import select

    from owlforge.engine.events import Emitter
    from owlforge.engine.validate import collapse_passive_findings, validate_findings
    from owlforge.store.models import Finding

    # validation runs first in the real pipeline; passive (no-repro) findings must
    # stay candidate AND keep their marker.
    asyncio.run(validate_findings(assessment_id="a", sandbox=None,
                                  emit=Emitter("a", persist=False)))
    with db.session() as s:
        csp = s.get(Finding, "csp0")
        assert csp.status == "candidate"
        assert "passive observation" in (csp.validation_note or "").lower()

    # and collapse still merges them afterwards
    n = collapse_passive_findings("a")
    assert n == 2
    with db.session() as s:
        live = [f for f in s.exec(select(Finding).where(Finding.assessment_id == "a")).all()
                if f.title == "Missing Content-Security-Policy" and f.status == "candidate"]
    assert len(live) == 1


def test_candidate_dup_of_validated_is_collapsed_not_rejected(tmp_path, monkeypatch):
    """A deterministic pass validates GraphQL introspection; the LLM specialist files the
    same thing as a candidate with a repro that won't re-reproduce. It must be collapsed
    as a duplicate, not re-probed and shown as 'rejected'."""
    import asyncio

    db = _db(tmp_path, monkeypatch)
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="det0", assessment_id="a", title="GraphQL introspection enabled",
                      severity="medium", status="validated", confidence="high",
                      endpoint="https://t/graphql", method="POST"))
        s.add(Finding(id="llm0", assessment_id="a", title="GraphQL introspection enabled",
                      severity="medium", status="candidate", method="POST",
                      repro_url="https://t/graphql", repro_method="POST",
                      repro_command="curl ...", success_signal="__schema"))
        s.commit()

    from owlforge.engine.events import Emitter
    from owlforge.engine.validate import validate_findings
    counts = asyncio.run(validate_findings(assessment_id="a", sandbox=None,
                                           emit=Emitter("a", persist=False)))
    assert counts["rejected"] == 0            # the dup was NOT rejected
    with db.session() as s:
        llm = s.get(Finding, "llm0")
        det = s.get(Finding, "det0")
    assert llm.status == "duplicate"
    assert det.status == "validated"
