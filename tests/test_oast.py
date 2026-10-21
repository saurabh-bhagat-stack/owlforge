"""P0 #2: out-of-band (OAST) blind SSRF/XXE via interactsh -> tunnel -> BYO (offline fakes).

The sandbox owns the long-lived provider via agentd /oast/*; the fake mimics that contract.
"""

from __future__ import annotations

import re


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _SB:
    """Fake sandbox implementing the agentd OAST contract. `interactsh`/`tunnel`/`byo`
    toggle which provider comes up; `callback` echoes injected tokens back as interactions."""

    DOMAIN = "cabc123def456ghij789.oast.pro"
    CF = "random-words-here.trycloudflare.com"
    OUT = "/workspace/oast.jsonl"
    HITS = "/workspace/oast_hits.log"

    def __init__(self, interactsh=True, tunnel=False, byo=False, callback=True):
        self.interactsh = interactsh
        self.tunnel = tunnel
        self.byo = byo
        self.callback = callback
        self.hits = ""
        self.injected = []

    def oast_start(self, provider="interactsh", *, server="", token="", ngrok_token=""):
        if provider == "interactsh":
            if server and "example" in server:            # a BYO collaborator domain
                return ({"domain": self.DOMAIN, "hits_file": self.OUT, "mode": "interactsh"}
                        if self.byo else {"error": "byo unreachable"})
            return ({"domain": self.DOMAIN, "hits_file": self.OUT, "mode": "interactsh"}
                    if self.interactsh else {"error": "interactsh unreachable"})
        if provider == "tunnel":
            return ({"domain": self.CF, "hits_file": self.HITS, "mode": "tunnel"}
                    if self.tunnel else {"error": "tunnel did not come up"})
        return {"error": "unknown provider"}

    def oast_poll(self, hits_file):
        return {"data": self.hits}

    def oast_stop(self):
        return {"stopped": True}

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        blob = f"{params} {body} {url}"
        for tok in re.findall(r"owl[0-9a-f]{8}", blob):
            self.injected.append(tok)
            if self.callback:
                self.hits += f'{{"full-id":"{tok}"}} {tok}\n'
        return {"status": 200, "body": ""}


def _cfg(**kw):
    from owlforge.config import OastConfig
    kw.setdefault("wait_seconds", 3)
    return OastConfig(**kw)


INV = [
    {"url": "https://t/fetch", "method": "GET", "params": ["url"]},
    {"url": "https://t/catalog/product/stock", "method": "POST", "params": ["productId", "storeId"]},
    {"url": "https://t/search", "method": "GET", "params": ["q"]},
]


def test_extract_targets():
    from owlforge.engine.oast import _ssrf_targets, _xxe_endpoints
    ss = {t["param"] for t in _ssrf_targets(INV)}
    assert "url" in ss and "storeId" in ss and "q" not in ss
    assert _xxe_endpoints(INV) == ["https://t/catalog/product/stock"]


def test_interactsh_first():
    from owlforge.engine.oast import OastSession
    sess = OastSession(_SB(interactsh=True, tunnel=True), _cfg())
    assert sess.start() and sess.mode == "interactsh" and sess.domain == _SB.DOMAIN
    assert sess.url("owldeadbeef") == f"http://owldeadbeef.{_SB.DOMAIN}/"


def test_tunnel_when_interactsh_blocked():
    from owlforge.engine.oast import OastSession
    sess = OastSession(_SB(interactsh=False, tunnel=True), _cfg())
    assert sess.start() and sess.mode == "tunnel" and sess.domain == _SB.CF
    assert sess.url("owldeadbeef") == f"https://{_SB.CF}/owldeadbeef"  # path token


def test_byo_when_auto_blocked():
    from owlforge.engine.oast import OastSession
    sess = OastSession(_SB(interactsh=False, tunnel=False, byo=True),
                       _cfg(collaborator_url="my.interactsh.example", token="t"))
    assert sess.start() and sess.source == "your configured collaborator"


def test_scan_files_blind_on_callback(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    assert oast_scan("a1", INV, _SB(callback=True), {}, _cfg()) >= 2
    with db.session() as s:
        titles = [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a1")).all()]
    assert any("Blind SSRF" in t for t in titles)
    assert any("XML external entity" in t for t in titles)


def test_scan_via_tunnel(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    assert oast_scan("a2", INV, _SB(interactsh=False, tunnel=True), {}, _cfg()) >= 1
    with db.session() as s:
        assert any("Blind SSRF" in f.title
                   for f in s.exec(select(Finding).where(Finding.assessment_id == "a2")).all())


def test_no_callback_files_nothing(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    assert oast_scan("a3", INV, _SB(callback=False), {}, _cfg()) == 0
    with db.session() as s:
        assert s.exec(select(Finding).where(Finding.assessment_id == "a3")).all() == []


def test_fallback_flags_and_names_config(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    msgs = []
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    n = oast_scan("a4", INV, _SB(interactsh=False, tunnel=False, byo=False), {}, _cfg(),
                  log=msgs.append)
    assert n >= 1
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a4")).all()
    assert all(f.status == "candidate" for f in rows)
    assert any("manual verification" in (f.validation_note or "") for f in rows)
    assert any("collaborator_url" in m and "[oast]" in m for m in msgs)
