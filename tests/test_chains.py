"""M9 exploit-chain correlation (deterministic, over validated components)."""

from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _asmt(db, aid="a"):
    from owlforge.store.models import Assessment
    with db.session() as s:
        s.add(Assessment(id=aid, project_name="p", target="https://t.example",
                         instructions="x", scan_mode="orchestrate"))
        s.commit()


def _add(db, aid, fid, title, status="validated", severity="high", endpoint="", poc=""):
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id=fid, assessment_id=aid, title=title, status=status,
                      severity=severity, endpoint=endpoint, proof_of_concept=poc))
        s.commit()


def _titles(db, aid):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == aid)).all()]


def test_creds_plus_access_control_makes_chain(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _asmt(db)
    _add(db, "a", "f1", "Broken access control (IDOR) on /orders/{id}",
         endpoint="/orders/5")
    from owlforge.engine.chains import correlate_chains
    n = correlate_chains("a", auth_summary="authenticated (login-page creds: carlos)")
    assert n == 1
    assert any(t.startswith("Exploit chain: credentialed access") for t in _titles(db, "a"))


def test_no_chain_when_unauthenticated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _asmt(db)
    _add(db, "a", "f1", "Broken access control (IDOR)")
    from owlforge.engine.chains import correlate_chains
    assert correlate_chains("a", auth_summary="unauthenticated") == 0


def test_ssrf_to_metadata_chain(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _asmt(db)
    _add(db, "a", "f1", "SSRF / open redirect on /fetch", severity="high",
         endpoint="/fetch?url=http://169.254.169.254/latest/meta-data/")
    from owlforge.engine.chains import correlate_chains
    n = correlate_chains("a", auth_summary="unauthenticated")
    titles = _titles(db, "a")
    assert n == 1
    chain = next(t for t in titles if t.startswith("Exploit chain: SSRF"))
    assert "metadata" in chain


def test_ssrf_without_metadata_no_chain(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _asmt(db)
    _add(db, "a", "f1", "SSRF on /fetch", endpoint="/fetch?url=http://example.org/")
    from owlforge.engine.chains import correlate_chains
    assert correlate_chains("a", auth_summary="unauthenticated") == 0


def test_idempotent_no_duplicate_chains(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _asmt(db)
    _add(db, "a", "f1", "Access control violation on /admin", endpoint="/admin")
    from owlforge.engine.chains import correlate_chains
    assert correlate_chains("a", auth_summary="authenticated") == 1
    assert correlate_chains("a", auth_summary="authenticated") == 0  # already exists
