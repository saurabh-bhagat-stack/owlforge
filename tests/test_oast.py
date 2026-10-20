"""P0 #2: out-of-band (OAST) blind SSRF/XXE via interactsh -> tunnel -> BYO (offline fakes)."""

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


def _ns(stdout):
    return SimpleNamespace(stdout=stdout, stderr="", exit_code=0)


class _SB:
    """Fake sandbox. `interactsh`/`tunnel` toggle which provider comes up; `callback` echoes
    injected tokens back as interactions; `installed` controls interactsh-client presence."""

    DOMAIN = "cabc123def456ghij789.oast.pro"
    CF = "random-words-here.trycloudflare.com"

    def __init__(self, interactsh=True, tunnel=False, callback=True, installed=True):
        self.interactsh = interactsh
        self.tunnel = tunnel
        self.callback = callback
        self.installed = installed
        self.hits = ""
        self.injected = []

    def exec(self, cmd, timeout_ms=0):
        if "-psf" in cmd:                                        # interactsh start
            if not self.installed:
                return _ns("__NO_INTERACTSH__\n")
            return _ns(f"{self.DOMAIN}\n" if self.interactsh else "")
        if "cloudflared tunnel" in cmd or "ngrok http" in cmd:   # tunnel start
            return _ns(f"https://{self.CF}\n" if self.tunnel else "")
        if "oast.jsonl" in cmd or "oast_hits.log" in cmd:        # collect
            return _ns(self.hits)
        return _ns("")

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


def test_interactsh_is_tried_first():
    from owlforge.engine.oast import OastSession
    sess = OastSession(_SB(interactsh=True, tunnel=True), _cfg())
    assert sess.start() is True
    assert sess.mode == "interactsh" and sess.domain == _SB.DOMAIN
    assert sess.url("owldeadbeef") == f"http://owldeadbeef.{_SB.DOMAIN}/"


def test_tunnel_used_when_interactsh_blocked():
    from owlforge.engine.oast import OastSession
    sess = OastSession(_SB(interactsh=False, tunnel=True), _cfg())
    assert sess.start() is True
    assert sess.mode == "tunnel" and sess.domain == _SB.CF
    assert sess.url("owldeadbeef") == f"https://{_SB.CF}/owldeadbeef"  # path token, not subdomain


def test_byo_collaborator_used_when_auto_blocked():
    from owlforge.engine.oast import OastSession
    sb = _SB(interactsh=False, tunnel=False)
    calls = {"n": 0}
    orig = sb.exec

    def exec_counting(cmd, timeout_ms=0):
        if "-psf" in cmd:
            calls["n"] += 1
            return _ns(_SB.DOMAIN + "\n") if calls["n"] >= 2 else _ns("")
        return orig(cmd, timeout_ms)

    sb.exec = exec_counting
    sess = OastSession(sb, _cfg(collaborator_url="my.interactsh.example", token="t"))
    assert sess.start() is True
    assert sess.source == "your configured collaborator"


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


def test_scan_via_tunnel_files_blind(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    assert oast_scan("a2", INV, _SB(interactsh=False, tunnel=True, callback=True), {}, _cfg()) >= 1
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a2")).all()
    assert any("Blind SSRF" in f.title for f in rows)


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
    n = oast_scan("a4", INV, _SB(installed=False, tunnel=False), {}, _cfg(), log=msgs.append)
    assert n >= 1
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a4")).all()
    assert all(f.status == "candidate" for f in rows)
    assert any("manual verification" in (f.validation_note or "") for f in rows)
    assert any("collaborator_url" in m and "[oast]" in m for m in msgs)
