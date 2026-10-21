"""OAST blind OS-command + out-of-band SQLi (extends the callback infra)."""
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
    DOMAIN = "cabc123def456ghij789.oast.pro"

    def __init__(self, callback=True):
        self.callback = callback
        self.hits = ""

    def oast_start(self, provider="interactsh", *, server="", token="", ngrok_token=""):
        return {"domain": self.DOMAIN, "hits_file": "/workspace/oast.jsonl", "mode": "interactsh"}

    def oast_poll(self, hits_file):
        return {"data": self.hits}

    def oast_stop(self):
        return {"stopped": True}

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        for tok in re.findall(r"owl[0-9a-f]{8}", f"{params} {body} {url}"):
            if self.callback:
                self.hits += f'{{"full-id":"{tok}"}} {tok}\n'
        return {"status": 200, "body": ""}


def _cfg():
    from owlforge.config import OastConfig
    return OastConfig(wait_seconds=3)


def test_blind_command_injection_confirmed(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    inv = [{"url": "https://t/ping", "method": "GET", "params": ["host"]}]  # host -> RCE class
    n = oast_scan("a1", inv, _SB(callback=True), {}, _cfg())
    with db.session() as s:
        titles = [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a1")).all()]
    assert any("command" in t.lower() for t in titles)
    assert n >= 1


def test_blind_oob_sqli_confirmed(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    inv = [{"url": "https://t/item", "method": "GET", "params": ["q"]}]  # any param -> SQLI class
    n = oast_scan("a2", inv, _SB(callback=True), {}, _cfg())
    with db.session() as s:
        titles = [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == "a2")).all()]
    assert any("sql injection" in t.lower() for t in titles)
    assert n >= 1


def test_no_callback_no_blind_findings(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr("owlforge.engine.oast.time.sleep", lambda *_: None)
    from sqlmodel import select

    from owlforge.engine.oast import oast_scan
    from owlforge.store.models import Finding
    inv = [{"url": "https://t/ping", "method": "GET", "params": ["host", "q"]}]
    assert oast_scan("a3", inv, _SB(callback=False), {}, _cfg()) == 0
    with db.session() as s:
        assert s.exec(select(Finding).where(Finding.assessment_id == "a3")).all() == []
