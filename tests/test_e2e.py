"""End-to-end integration: run the REAL deterministic pipeline (not fakes) against a tiny,
dependency-free, deliberately-vulnerable in-process app, through the actual sandbox
interface. This is the closest thing to a live run in CI — it exercises how register ->
seed -> model -> attack passes wire together, catching integration breakage the unit tests
(which stub one pass at a time) cannot.

The app has, on purpose: mass assignment at register and on posts, client-controlled
ownership, broken object/function-level authz (IDOR + non-owner edit/delete), a body-driven
workflow state, and a racy single-use coupon.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
from urllib.parse import parse_qs, urlsplit

TARGET = "http://app.local"


class VulnApp:
    def __init__(self):
        self.users = {}          # sid -> {id, email, role}
        self.posts = {}          # pid -> {...}
        self.pid = 0
        self.coupon_used = 0
        self._lock = threading.Lock()

    def _user(self, headers):
        m = re.search(r"sid=([A-Za-z0-9]+)", (headers or {}).get("Cookie", ""))
        return self.users.get(m.group(1)) if m else None

    @staticmethod
    def _data(body, ct):
        if "json" in (ct or ""):
            try:
                return json.loads(body or "{}")
            except Exception:
                return {}
        return {k: v[0] for k, v in parse_qs(body or "").items()}

    def _post_html(self, pid):
        p = self.posts[pid]
        rows = "".join(f"<div>{k}: {v}</div>" for k, v in p.items())
        return (f"<html>{rows}"
                f'<form action="/posts/{pid}" method="post">'
                f'<input name="title" value="{p.get("title", "")}"></form>'
                f'<a href="/posts/{pid}/delete">delete</a></html>')

    def handle(self, method, path, headers, body, ct, query):
        data = self._data(body, ct)

        if path == "/register" and method == "GET":
            return {"status": 200, "headers": {}, "body":
                    '<form action="/register" method="post">'
                    '<input name="email"><input name="username">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password"></form>'}
        if path == "/register" and method == "POST":
            sid = secrets.token_hex(8)
            uid = len(self.users) + 1
            # VULN: role is mass-assigned straight from the request
            self.users[sid] = {"id": uid, "email": data.get("email", ""),
                               "role": data.get("role", "user")}
            return {"status": 302, "headers": {"location": "/me"},
                    "set_cookie": [f"sid={sid}; Path=/"], "body": ""}
        if path == "/me" and method == "GET":
            u = self._user(headers)
            if not u:
                return {"status": 401, "headers": {}, "body": "login"}
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": json.dumps(u)}

        if path == "/posts" and method == "GET":
            return {"status": 200, "headers": {}, "body":
                    '<form action="/posts" method="post">'
                    '<input name="title" value=""><textarea name="body"></textarea></form>'}
        if path == "/posts" and method == "POST":
            u = self._user(headers)
            self.pid += 1
            post = {"id": self.pid, "title": data.get("title", ""),
                    "body": data.get("body", ""), "owner": u["id"] if u else 0,
                    "status": "draft"}
            for k, v in data.items():          # VULN: mass-assign every posted field
                if k not in ("title", "body"):
                    post[k] = v
            self.posts[self.pid] = post
            return {"status": 302, "headers": {"location": f"/posts/{self.pid}"}, "body": ""}

        m = re.match(r"^/posts/(\d+)$", path)
        if m:
            pid = int(m.group(1))
            if pid not in self.posts:
                return {"status": 404, "headers": {}, "body": "not found"}
            if method == "GET":                # VULN: IDOR — anyone can read
                return {"status": 200, "headers": {}, "body": self._post_html(pid)}
            if method == "POST":               # VULN: BFLA — any caller can edit, mass-assign
                for k, v in data.items():
                    self.posts[pid][k] = v
                return {"status": 302, "headers": {"location": f"/posts/{pid}"}, "body": ""}
        m = re.match(r"^/posts/(\d+)/delete$", path)
        if m:                                  # VULN: BFLA — any caller can delete
            self.posts.pop(int(m.group(1)), None)
            return {"status": 302, "headers": {"location": "/posts"}, "body": ""}

        if path == "/coupon/redeem" and method == "POST":   # VULN: racy single-use
            seen = self.coupon_used
            time.sleep(0.02)
            if seen >= 1:
                return {"status": 409, "headers": {}, "body": "already redeemed"}
            self.coupon_used = seen + 1
            return {"status": 200, "headers": {},
                    "body": json.dumps({"receipt": secrets.token_hex(4)})}

        return {"status": 404, "headers": {}, "body": "not found"}


class E2ESandbox:
    """Adapts owlforge's sandbox.http_request / render to the in-process app."""

    def __init__(self, app):
        self.app = app

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        sp = urlsplit(url)
        ct = (headers or {}).get("Content-Type", "")
        return self.app.handle(method, sp.path, headers or {}, body or "", ct, {})

    def render(self, url, *, headers=None, timeout_ms=30000):
        r = self.app.handle("GET", urlsplit(url).path, headers or {}, "", "", {})
        return {"html": r.get("body", ""), "final_url": url}


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def _titles(db, aid):
    from sqlmodel import select

    from owlforge.store.models import Finding
    with db.session() as s:
        return [f.title for f in s.exec(select(Finding).where(Finding.assessment_id == aid)).all()]


def test_full_pipeline_against_vulnerable_app(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.appmodel import build_app_model
    from owlforge.engine.authmatrix import access_matrix_scan
    from owlforge.engine.raceprobe import race_scan
    from owlforge.engine.scenarios import (
        mass_assignment_scan,
        register_privilege_scan,
        workflow_bypass_scan,
    )
    from owlforge.engine.seed import register_account, seed_objects
    from owlforge.store.models import SurfaceItem

    aid = "e2e"
    app = VulnApp()
    sb = E2ESandbox(app)
    inv = [
        {"url": f"{TARGET}/register", "method": "POST", "source": "form",
         "params": ["email", "password", "confirm_password"]},
        {"url": f"{TARGET}/posts", "method": "POST", "source": "form",
         "params": ["title", "body"]},
        {"url": f"{TARGET}/coupon/redeem", "method": "POST", "source": "form", "params": []},
    ]

    # 1) register two throwaway accounts (register + session + two-user setup)
    rega = register_account(inv, sb, TARGET)
    regb = register_account(inv, sb, TARGET)
    assert rega and regb and rega["headers"] != regb["headers"]
    rega["label"], regb["label"] = "user-a", "user-b"
    session = rega["headers"]

    # 2) seed an object as user-a, persist it as surface
    seeded = seed_objects(inv, sb, session, TARGET)
    assert seeded, "seeding should create a post and capture its id"
    with db.session() as s:
        for i, it in enumerate(seeded):
            s.add(SurfaceItem(id=f"sf{i}", assessment_id=aid, url=it["url"],
                              method="GET", params=[], source="seeded"))
        s.commit()

    # 3) build the app model
    model = build_app_model(inv + seeded, [rega, regb], [it["url"] for it in seeded])
    assert model.is_interesting()

    # 4) attack passes against the REAL app
    assert mass_assignment_scan(aid, model, sb, session) >= 1
    assert register_privilege_scan(aid, inv, sb, TARGET) == 1
    assert workflow_bypass_scan(aid, model, sb, session) >= 1
    assert race_scan(aid, model, sb, session, burst=6) == 1
    assert access_matrix_scan(aid, sb, session, [rega, regb]) >= 1   # deletes the post last

    titles = " || ".join(_titles(db, aid)).lower()
    assert "mass assignment" in titles
    assert "registration" in titles           # privilege escalation at registration
    assert "workflow step bypass" in titles
    assert "race condition" in titles
    assert "function-level authorization" in titles or "ownership" in titles
