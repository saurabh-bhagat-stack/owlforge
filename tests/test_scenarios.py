"""Scenario engine — mass-assignment (validated via differential) + the business-logic brief."""
from __future__ import annotations

import re
from urllib.parse import parse_qs


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


class _CreateApp:
    """POST /posts creates an object; with `bind` it mass-assigns unknown fields onto it."""

    def __init__(self, bind):
        self.bind = bind
        self.n = 0
        self.store = {}

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/posts") and method == "GET":
            return {"status": 200, "headers": {}, "body":
                    '<form action="/posts" method="post">'
                    '<input name="title" value=""><textarea name="body"></textarea></form>'}
        if url.endswith("/posts") and method == "POST":
            q = {k: v[0] for k, v in parse_qs(body or "").items()}
            self.n += 1
            obj = {"title": q.get("title", ""), "body": q.get("body", "")}
            if self.bind:
                for extra in ("role", "balance", "is_admin"):
                    if extra in q:
                        obj[extra] = q[extra]
            self.store[self.n] = obj
            return {"status": 302, "headers": {"location": f"/posts/{self.n}"}, "body": ""}
        m = re.search(r"/posts/(\d+)$", url)
        if m and method == "GET":
            o = self.store.get(int(m.group(1)))
            if not o:
                return {"status": 404, "headers": {}, "body": "nf"}
            parts = [f'<div class="title">{o["title"]}</div>']
            for k in ("role", "balance", "is_admin"):
                if k in o:
                    parts.append(f"<span>{k}: {o[k]}</span>")
            return {"status": 200, "headers": {}, "body": "<html>" + "".join(parts) + "</html>"}
        return {"status": 404, "headers": {}, "body": ""}


class _EditApp:
    """POST /account updates a profile; with `bind` it mass-assigns `role`."""

    def __init__(self, bind):
        self.bind = bind
        self.p = {"name": "foo"}

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/account") and method == "GET":
            parts = [f'<form action="/account" method="post">'
                     f'<input name="name" value="{self.p["name"]}"></form>',
                     f'<div>name: {self.p["name"]}</div>']
            if "role" in self.p:
                parts.append(f'<div>role: {self.p["role"]}</div>')
            return {"status": 200, "headers": {}, "body": "<html>" + "".join(parts) + "</html>"}
        if url.endswith("/account") and method == "POST":
            q = {k: v[0] for k, v in parse_qs(body or "").items()}
            self.p["name"] = q.get("name", self.p["name"])
            if self.bind and "role" in q:
                self.p["role"] = q["role"]
            return {"status": 302, "headers": {"location": "/account"}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}


def _model_create():
    from owlforge.engine.appmodel import build_app_model
    return build_app_model(
        [{"url": "https://t/posts", "method": "POST", "params": ["title", "body"], "source": "form"}],
        [{"label": "session", "role": "user", "headers": SESS}])


def _model_edit():
    from owlforge.engine.appmodel import build_app_model
    return build_app_model(
        [{"url": "https://t/account", "method": "POST", "params": ["name"], "source": "form"}],
        [{"label": "session", "role": "user", "headers": SESS}])


def test_mass_assignment_create_validated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    n = mass_assignment_scan("a", _model_create(), _CreateApp(bind=True), SESS)
    assert n >= 1
    f = _findings(db)
    assert any("Mass assignment" in x.title and x.status == "validated" for x in f)


def test_mass_assignment_create_secure_is_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    n = mass_assignment_scan("a", _model_create(), _CreateApp(bind=False), SESS)
    assert n == 0
    assert _findings(db) == []


def test_mass_assignment_edit_validated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    n = mass_assignment_scan("a", _model_edit(), _EditApp(bind=True), SESS)
    assert n >= 1
    assert any(x.status == "validated" for x in _findings(db))


def test_mass_assignment_edit_secure_is_quiet(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    n = mass_assignment_scan("a", _model_edit(), _EditApp(bind=False), SESS)
    assert n == 0


def test_needs_session():
    from owlforge.engine.scenarios import mass_assignment_scan
    assert mass_assignment_scan("a", _model_create(), _CreateApp(bind=True), {}) == 0


def test_business_logic_brief_mentions_hypotheses():
    from owlforge.engine.scenarios import business_logic_brief
    brief = business_logic_brief(_model_create())
    assert "BUSINESS-LOGIC" in brief
    assert "PRICE/QUANTITY" in brief
    assert "create_finding" in brief


def test_specialist_skips_without_client():
    import asyncio

    from owlforge.engine.scenarios import run_business_logic_specialist
    n = asyncio.run(run_business_logic_specialist(
        client=None, sandbox=None, assessment_id="a", target="https://t",
        model=_model_create(), emit=lambda *a, **k: None, session_headers=SESS))
    assert n == 0
