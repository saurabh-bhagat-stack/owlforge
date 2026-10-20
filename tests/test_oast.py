"""P0 #2: out-of-band (OAST) blind SSRF/XXE detection via interactsh (offline fakes)."""

from __future__ import annotations

import re
from types import SimpleNamespace


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    """Fake sandbox: serves a callback domain on start, records injected tokens, and (when
    callback=True) echoes them back as interactions — simulating a target that calls back."""

    DOMAIN = "cabc123def456ghij789.oast.pro"

    def __init__(self, callback=True, installed=True):
        self.callback = callback
        self.installed = installed
        self.jsonl = ""
        self.injected = []

    def exec(self, cmd, timeout_ms=0):
        if "-psf" in cmd:  # start interactsh-client
            if not self.installed:
                return SimpleNamespace(stdout="__NO_INTERACTSH__\n", stderr="", exit_code=0)
            return SimpleNamespace(stdout=f"{self.DOMAIN}\n---\n[INF] Listing 1 payload\n",
                                   stderr="", exit_code=0)
        if "oast.jsonl" in cmd:  # collect
            return SimpleNamespace(stdout=self.jsonl, stderr="", exit_code=0)
        return SimpleNamespace(stdout="", stderr="", exit_code=0)

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        blob = f"{params} {body} {url}"
        for tok in re.findall(r"owl[0-9a-f]{8}", blob):
            self.injected.append(tok)
            if self.callback:
                self.jsonl += f'{{"protocol":"http","full-id":"{tok}.{self.DOMAIN}"}}\n'
        return {"status": 200, "body": ""}


def _cfg(**kw):
    from owlforge.config import OastConfig
    return OastConfig(wait_seconds=3, **kw)


INV = [
    {"url": "https://t/fetch", "method": "GET", "params": ["url"]},        # SSRF param
    {"url": "https://t/catalog/product/stock", "method": "POST", "params": ["productId", "storeId"]},
    {"url": "https://t/search", "method": "GET", "params": ["q"]},         # not SSRF
]


def test_extract_targets():
    from owlforge.engine.oast import _ssrf_targets, _xxe_endpoints
    ss = {(t["param"]) for t in _ssrf_targets(INV)}
    assert "url" in ss and "storeId" in ss and "q" not in ss
    assert _xxe_endpoints(INV) == ["https://t/catalog/product/stock"]


def test_session_start_parses_domain():
    from owlforge.engine.oast import OastSession
    sess = OastSession(_SB(), _cfg())
    assert sess.start() is True
    assert sess.domain == _SB.DOMAIN and sess.available
    assert sess.url("owldeadbeef").startswith(f"http://owldeadbeef.{_SB.DOMAIN}")


def test_session_start_false_without_interactsh():
    from owlforge.engine.oast import OastSession
    assert OastSession(_SB(installed=False), _cfg()).start() is False


def test_oast_scan_files_blind_findings_on_callback(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    n = oast_scan("a1", INV, _SB(callback=True), {}, _cfg())
    assert n >= 2
    with db.session() as s:
        titles = [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a1")).all()]
    assert any("Blind SSRF" in t for t in titles)
    assert any("XML external entity" in t for t in titles)


def test_oast_scan_no_callback_files_nothing(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    n = oast_scan("a2", INV, _SB(callback=False), {}, _cfg())
    assert n == 0
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a2")).all()
    assert rows == []


def test_fallback_flags_when_no_oast(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    # interactsh not installed -> start() False -> fallback flags SSRF-hint sinks as candidates
    n = oast_scan("a3", INV, _SB(installed=False), {}, _cfg())
    assert n >= 1
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a3")).all()
    assert all(f.status == "candidate" for f in rows)
    assert any("manual verification" in (f.validation_note or "") for f in rows)
