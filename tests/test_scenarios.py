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


# ---- client-controlled ownership (candidate) --------------------------------------------
class _OwnApp:
    """POST /posts stores a client-supplied author_id (ownership tampering)."""

    def __init__(self):
        self.n = 0
        self.store = {}

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/posts") and method == "GET":
            return {"status": 200, "headers": {}, "body":
                    '<form action="/posts" method="post"><input name="title" value=""></form>'}
        if url.endswith("/posts") and method == "POST":
            q = {k: v[0] for k, v in parse_qs(body or "").items()}
            self.n += 1
            obj = {"title": q.get("title", "")}
            if "author_id" in q:
                obj["author_id"] = q["author_id"]
            self.store[self.n] = obj
            return {"status": 302, "headers": {"location": f"/posts/{self.n}"}, "body": ""}
        m = re.search(r"/posts/(\d+)$", url)
        if m and method == "GET":
            o = self.store.get(int(m.group(1)))
            if not o:
                return {"status": 404, "headers": {}, "body": "nf"}
            parts = [f'<div>{o["title"]}</div>']
            if "author_id" in o:
                parts.append(f'<span>author_id: {o["author_id"]}</span>')
            return {"status": 200, "headers": {}, "body": "<html>" + "".join(parts) + "</html>"}
        return {"status": 404, "headers": {}, "body": ""}


def test_ownership_spoof_is_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    n = mass_assignment_scan("a", _model_create(), _OwnApp(), SESS)
    assert n >= 1
    f = _findings(db)
    assert any("ownership" in x.title.lower() and x.status == "candidate" for x in f)


# ---- privilege escalation at registration -----------------------------------------------
class _RegApp:
    """Sign-up that auto-starts a session; with `bind` it mass-assigns `role` at sign-up."""

    def __init__(self, bind, auto_session=True):
        self.bind = bind
        self.auto = auto_session
        self.n = 0
        self.accts = {}

    def _sid(self, headers):
        c = (headers or {}).get("Cookie", "")
        m = re.search(r"sess=(\d+)", c)
        return int(m.group(1)) if m else None

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/register") and method == "GET":
            return {"status": 200, "headers": {}, "body":
                    '<form action="/register" method="post">'
                    '<input name="email"><input name="password" type="password"></form>'}
        if url.endswith("/register") and method == "POST":
            q = {k: v[0] for k, v in parse_qs(body or "").items()}
            self.n += 1
            acct = {"email": q.get("email", "")}
            if self.bind and "role" in q:
                acct["role"] = q["role"]
            self.accts[self.n] = acct
            resp = {"status": 302, "headers": {"location": "/me"}, "body": ""}
            if self.auto:
                resp["set_cookie"] = [f"sess={self.n}; Path=/"]
            return resp
        if url.endswith("/me") and method == "GET":
            acct = self.accts.get(self._sid(headers))
            if not acct:
                return {"status": 401, "headers": {}, "body": "login"}
            parts = [f'<div>email: {acct["email"]}</div>']
            if "role" in acct:
                parts.append(f'<div>role: {acct["role"]}</div>')
            return {"status": 200, "headers": {}, "body": "<html>" + "".join(parts) + "</html>"}
        return {"status": 404, "headers": {}, "body": ""}


_REG_INV = [{"url": "https://t/register", "method": "POST",
             "params": ["email", "password"], "source": "form"}]


def test_register_privilege_escalation_validated(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import register_privilege_scan
    n = register_privilege_scan("a", _REG_INV, _RegApp(bind=True), "https://t")
    assert n == 1
    assert any("registration" in x.title.lower() and x.status == "validated" for x in _findings(db))


def test_register_secure_is_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import register_privilege_scan
    n = register_privilege_scan("a", _REG_INV, _RegApp(bind=False), "https://t")
    assert n == 0
    assert _findings(db) == []


def test_register_no_autosession_skips(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import register_privilege_scan
    n = register_privilege_scan("a", _REG_INV, _RegApp(bind=True, auto_session=False), "https://t")
    assert n == 0


# ---- unauthenticated privileged action --------------------------------------------------
class _TransApp:
    def __init__(self, require_auth):
        self.ra = require_auth

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/posts/5/approve") and method == "POST":
            if self.ra and not (headers or {}).get("Cookie"):
                return {"status": 403, "headers": {}, "body": "forbidden"}
            return {"status": 302, "headers": {"location": "/posts/5"}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}


def _model_transition():
    from owlforge.engine.appmodel import build_app_model
    return build_app_model(
        [{"url": "https://t/posts/5/approve", "method": "POST", "params": [], "source": "form"}],
        [{"label": "session", "role": "user", "headers": SESS}])


def test_unauth_action_is_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import unauth_action_scan
    n = unauth_action_scan("a", _model_transition(), _TransApp(require_auth=False), SESS)
    assert n >= 1
    assert any("without authentication" in x.title and x.status == "candidate" for x in _findings(db))


def test_unauth_action_secure_is_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import unauth_action_scan
    n = unauth_action_scan("a", _model_transition(), _TransApp(require_auth=True), SESS)
    assert n == 0
    assert _findings(db) == []


# ---- nested-JSON proof awareness --------------------------------------------------------
def test_reflects_nested_json():
    from owlforge.engine.scenarios import _reflects
    assert _reflects('{"data":{"user":{"role":"admin"}}}', "role", "admin")
    assert _reflects('{"account":{"is_admin":true}}', "is_admin", "true")
    assert _reflects('{"o":{"balance":7000123}}', "balance", "7000123")
    assert not _reflects('{"user":{"name":"bob"}}', "role", "admin")
    assert _reflects("<span>role: admin</span>", "role", "admin")  # html path intact


class _CreateJsonApp:
    """Form create, but the stored object is served back as (nested) JSON."""

    def __init__(self, bind):
        self.bind = bind
        self.n = 0
        self.store = {}

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/posts") and method == "GET":
            return {"status": 200, "headers": {}, "body":
                    '<form action="/posts" method="post"><input name="title" value=""></form>'}
        if url.endswith("/posts") and method == "POST":
            q = {k: v[0] for k, v in parse_qs(body or "").items()}
            self.n += 1
            obj = {"title": q.get("title", "")}
            if self.bind and "role" in q:
                obj["role"] = q["role"]
            self.store[self.n] = obj
            return {"status": 302, "headers": {"location": f"/posts/{self.n}"}, "body": ""}
        m = re.search(r"/posts/(\d+)$", url)
        if m and method == "GET":
            o = self.store.get(int(m.group(1)))
            if not o:
                return {"status": 404, "headers": {}, "body": "{}"}
            import json as _j
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": _j.dumps({"data": {"post": o}})}
        return {"status": 404, "headers": {}, "body": ""}


def test_mass_assignment_detected_in_json_read(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    assert mass_assignment_scan("a", _model_create(), _CreateJsonApp(bind=True), SESS) >= 1
    assert any("Mass assignment" in x.title for x in _findings(db))


def test_mass_assignment_json_secure_quiet(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    assert mass_assignment_scan("a", _model_create(), _CreateJsonApp(bind=False), SESS) == 0


# ---- deterministic workflow step-bypass -------------------------------------------------
def _seed_surface(db, url="https://t/orders/5"):
    from owlforge.store.models import SurfaceItem
    with db.session() as s:
        s.add(SurfaceItem(id="sf1", assessment_id="a", url=url, method="GET",
                          params=[], source="seeded"))
        s.commit()


class _WFApp:
    """An order in 'draft'; POST .../approve either applies (-> 'approved') or is forbidden."""

    def __init__(self, allow):
        self.allow = allow
        self.state = "draft"

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/orders/5") and method == "GET":
            return {"status": 200, "headers": {}, "body": f"<div>state: {self.state}</div>"}
        if url.endswith("/orders/5/approve") and method == "POST":
            if not self.allow:
                return {"status": 403, "headers": {}, "body": "forbidden"}
            self.state = "approved"
            return {"status": 302, "headers": {"location": "/orders/5"}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}


def test_workflow_bypass_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed_surface(db)
    from owlforge.engine.scenarios import workflow_bypass_scan
    n = workflow_bypass_scan("a", _model_transition(), _WFApp(allow=True), SESS)
    assert n >= 1
    assert any("workflow step bypass" in x.title.lower() and x.status == "candidate"
               for x in _findings(db))


def test_workflow_bypass_secure_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed_surface(db)
    from owlforge.engine.scenarios import workflow_bypass_scan
    assert workflow_bypass_scan("a", _model_transition(), _WFApp(allow=False), SESS) == 0
    assert _findings(db) == []


# ---- mass assignment on a pure-JSON API (no HTML form) ----------------------------------
class _JsonApiApp:
    """JSON API: POST /api/posts takes a JSON body; with `bind` it mass-assigns `role`."""

    def __init__(self, bind):
        self.bind = bind
        self.n = 0
        self.store = {}

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        import json as _j
        if url.endswith("/api/posts") and method == "GET":
            return {"status": 200, "headers": {}, "body": "{}"}        # no HTML form
        if url.endswith("/api/posts") and method == "POST":
            obj = _j.loads(body or "{}")
            self.n += 1
            rec = {"title": obj.get("title", "")}
            if self.bind and "role" in obj:
                rec["role"] = obj["role"]
            self.store[self.n] = rec
            return {"status": 201, "headers": {"location": f"/api/posts/{self.n}"},
                    "body": _j.dumps({"id": self.n})}
        m = re.search(r"/api/posts/(\d+)$", url)
        if m and method == "GET":
            o = self.store.get(int(m.group(1)))
            if not o:
                return {"status": 404, "headers": {}, "body": "{}"}
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": _j.dumps({"data": {"post": o}})}
        return {"status": 404, "headers": {}, "body": "{}"}


def _model_json_api():
    from owlforge.engine.appmodel import build_app_model
    return build_app_model(
        [{"url": "https://t/api/posts", "method": "POST", "params": ["title"], "source": "api-spec"}],
        [{"label": "session", "role": "user", "headers": SESS}])


def test_mass_assignment_json_api_create(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    assert mass_assignment_scan("a", _model_json_api(), _JsonApiApp(bind=True), SESS) >= 1
    assert any("Mass assignment" in x.title for x in _findings(db))


def test_mass_assignment_json_api_secure_quiet(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.scenarios import mass_assignment_scan
    assert mass_assignment_scan("a", _model_json_api(), _JsonApiApp(bind=False), SESS) == 0


# ---- body-driven workflow state bypass --------------------------------------------------
class _WFBodyApp:
    """An order whose state is set via a body field (status=approved), no /verb endpoint."""

    def __init__(self, allow):
        self.allow = allow
        self.status = "draft"

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if url.endswith("/orders/7") and method == "GET":
            return {"status": 200, "headers": {}, "body": f"<div>status: {self.status}</div>"}
        if url.endswith("/orders/7") and method == "POST":
            if self.allow and "status=approved" in (body or ""):
                self.status = "approved"
                return {"status": 200, "headers": {}, "body": "ok"}
            return {"status": 200, "headers": {}, "body": "ok"}   # accepts but ignores (secure)
        return {"status": 404, "headers": {}, "body": ""}


def test_workflow_bypass_body_driven_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed_surface(db, url="https://t/orders/7")
    from owlforge.engine.scenarios import workflow_bypass_scan
    assert workflow_bypass_scan("a", _model_transition(), _WFBodyApp(allow=True), SESS) >= 1
    assert any("workflow step bypass" in x.title.lower() for x in _findings(db))


def test_workflow_bypass_body_driven_secure_quiet(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed_surface(db, url="https://t/orders/7")
    from owlforge.engine.scenarios import workflow_bypass_scan
    assert workflow_bypass_scan("a", _model_transition(), _WFBodyApp(allow=False), SESS) == 0
    assert _findings(db) == []
