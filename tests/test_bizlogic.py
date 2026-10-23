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


class _CouponApp:
    def __init__(self, valid_any, reusable=True):
        self.valid_any = valid_any
        self.reusable = reusable
        self.used = False

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        blob = f"{params} {body}"
        if "OWLSAVE50" in blob:
            if not self.valid_any:
                return {"status": 200, "body": "Invalid coupon code"}
            if self.used and not self.reusable:
                return {"status": 200, "body": "coupon already used"}
            self.used = True
            return {"status": 200, "body": "Discount applied, you saved 50%"}
        return {"status": 200, "body": "ok"}


COUPON_INV = [{"url": "https://t/checkout", "method": "POST", "params": ["coupon"]}]


def test_weak_coupon_flagged(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.bizlogic import coupon_scan
    from owlforge.store.models import Finding
    assert coupon_scan("c1", COUPON_INV, _CouponApp(valid_any=True), {}) == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "c1")).one()
    assert "coupon" in f.title.lower() and f.status == "candidate"


def test_strict_coupon_quiet(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.bizlogic import coupon_scan
    assert coupon_scan("c2", COUPON_INV, _CouponApp(valid_any=False), {}) == 0
