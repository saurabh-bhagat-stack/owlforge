"""Business-logic: conservative negative-value (money/quantity) candidate probe."""

from __future__ import annotations


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    """Fake: a negative value is either accepted (reflected, no error) or rejected."""

    def __init__(self, reject=False):
        self.reject = reject

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        blob = f"{params} {body}"
        if "-1" in blob:
            if self.reject:
                return {"status": 200, "body": "Error: amount must be positive " * 4}
            return {"status": 200, "body": "cart updated: total is -1 now " * 4}
        return {"status": 200, "body": "cart updated: total is 1 now " * 4}


INV = [
    {"url": "https://t/cart", "method": "POST", "params": ["amount"]},   # money param
    {"url": "https://t/search", "method": "GET", "params": ["q"]},       # not money
]


def test_negative_accepted_flags_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.bizlogic import bizlogic_scan
    from owlforge.store.models import Finding
    n = bizlogic_scan("a1", INV, _SB(reject=False), {})
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a1")).one()
    assert f.status == "candidate" and f.confidence == "low"
    assert "amount" in f.title and f.endpoint == "https://t/cart"
    assert "manual verification" in (f.validation_note or "")


def test_negative_rejected_no_finding(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.bizlogic import bizlogic_scan
    from owlforge.store.models import Finding
    assert bizlogic_scan("a2", INV, _SB(reject=True), {}) == 0
    with db.session() as s:
        assert s.exec(select(Finding).where(Finding.assessment_id == "a2")).all() == []


def test_noop_without_money_params(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.bizlogic import bizlogic_scan
    inv = [{"url": "https://t/search", "method": "GET", "params": ["q"]}]
    assert bizlogic_scan("a3", inv, _SB(), {}) == 0
    assert bizlogic_scan("a4", INV, None, {}) == 0  # no sandbox


class _Echo:
    """Reflects whatever value is sent, with no validation error (accepts everything)."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        return {"status": 200, "body": f"cart updated: {params} {body}"}


def test_zero_and_fractional_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.bizlogic import bizlogic_scan
    from owlforge.store.models import Finding
    n = bizlogic_scan("a5", INV, _Echo(), {})
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "a5")).one()
    assert "amount" in f.title
    assert "0.01" in f.proof_of_concept and "-1" in f.proof_of_concept
