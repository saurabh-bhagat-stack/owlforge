"""Race-condition probe: concurrency bypass of a single-use action (candidate)."""
from __future__ import annotations

import threading
import time


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _findings(db):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return s.exec(select(Finding).where(Finding.assessment_id == "a")).all()


SESS = {"Cookie": "s=1"}


class _RedeemApp:
    """A single-use /coupon/redeem. If `racy`, the check-then-act has no lock (a concurrent
    burst all read used==0 before any writes); otherwise a lock serialises it."""

    def __init__(self, racy):
        self.racy = racy
        self.used = 0
        self._lock = threading.Lock()

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if not url.endswith("/coupon/redeem"):
            return {"status": 404, "headers": {}, "body": ""}
        if self.racy:
            seen = self.used                 # read
            time.sleep(0.03)                 # window during which others also read
            if seen >= 1:
                return {"status": 409, "headers": {}, "body": "already redeemed"}
            self.used = seen + 1             # non-atomic write
            return {"status": 200, "headers": {}, "body": "redeemed"}
        with self._lock:
            if self.used >= 1:
                return {"status": 409, "headers": {}, "body": "already redeemed"}
            self.used += 1
            return {"status": 200, "headers": {}, "body": "redeemed"}


def _model():
    from owlforge.engine.appmodel import build_app_model
    return build_app_model(
        [{"url": "https://t/coupon/redeem", "method": "POST", "params": [], "source": "form"}],
        [{"label": "session", "role": "user", "headers": SESS}])


def test_racy_single_use_flags_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.raceprobe import race_scan
    n = race_scan("a", _model(), _RedeemApp(racy=True), SESS, burst=6)
    assert n == 1
    f = _findings(db)
    assert any("race condition" in x.title.lower() and x.status == "candidate" for x in f)


def test_locked_single_use_is_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.raceprobe import race_scan
    n = race_scan("a", _model(), _RedeemApp(racy=False), SESS, burst=6)
    assert n == 0
    assert _findings(db) == []


def test_race_requires_session():
    from owlforge.engine.raceprobe import race_scan
    assert race_scan("a", _model(), _RedeemApp(racy=True), {}) == 0


class _RedeemReceiptApp:
    """Racy single-use redeem that returns a UNIQUE receipt id on each success, so a burst
    leaves multiple distinct side effects (confirms the action really ran more than once)."""

    def __init__(self):
        self.used = 0

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        import secrets as _s
        if not url.endswith("/coupon/redeem"):
            return {"status": 404, "headers": {}, "body": ""}
        seen = self.used
        time.sleep(0.03)
        if seen >= 1:
            return {"status": 409, "headers": {}, "body": "already redeemed"}
        self.used = seen + 1
        rid = _s.token_hex(4)
        return {"status": 200, "headers": {}, "body": f'{{"receipt":"{rid}"}}'}


def test_distinct_effects_raise_confidence(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.raceprobe import race_scan
    assert race_scan("a", _model(), _RedeemReceiptApp(), SESS, burst=6) == 1
    f = _findings(db)
    assert any(x.confidence == "medium" for x in f)
    assert any("distinct" in (x.proof_of_concept or "").lower() for x in f)
