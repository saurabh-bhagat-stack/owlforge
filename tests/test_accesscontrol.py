"""Authenticated access-control / IDOR scan: sound 3-way (owner/other/anon) differential."""

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
    """Fake sandbox. Response depends on URL + which identity (Cookie u=A/u=B, else anon).

    Scenarios:
      /catalog?productId=1  public      -> 200 same for everyone (must NOT be flagged)
      /my-account           anon-open   -> 200 same for everyone (account-scoped -> flagged)
      /orders/123           IDOR        -> A & B see the same order; anon redirected (flagged)
      /orders/999           protected   -> only A; anon redirect; B forbidden (NOT flagged)
    """

    def _who(self, headers):
        ck = (headers or {}).get("Cookie", "")
        return "A" if "u=A" in ck else "B" if "u=B" in ck else "anon"

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        who = self._who(headers)
        if "productId=1" in url or url.rstrip("/").endswith("/catalog"):
            return {"status": 200, "body": "PUBLIC CATALOG ITEM DETAILS " * 6}
        if "/my-account" in url:
            return {"status": 200, "body": "ACCOUNT PANEL FOR ALICE EMAIL ORDERS " * 6}
        if "/orders/123" in url:
            if who == "anon":
                return {"status": 302, "body": "please log in to continue " * 6}
            return {"status": 200, "body": "ORDER 123 ITEMS TOTAL ADDRESS " * 6}
        if "/orders/999" in url:
            if who == "A":
                return {"status": 200, "body": "ORDER 999 OWNER PRIVATE DATA " * 6}
            if who == "anon":
                return {"status": 302, "body": "please log in " * 6}
            return {"status": 403, "body": "forbidden " * 6}
        return {"status": 404, "body": ""}


INV = [
    {"url": "https://t/catalog?productId=1", "method": "GET", "params": ["productId"]},
    {"url": "https://t/my-account", "method": "GET", "params": []},
    {"url": "https://t/orders/123", "method": "GET", "params": []},
    {"url": "https://t/orders/999", "method": "GET", "params": []},
    {"url": "https://t/about", "method": "GET", "params": []},  # not an object endpoint
]

IDS = [
    {"label": "alice", "role": "user", "headers": {"Cookie": "u=A"}},
    {"label": "bob", "role": "user", "headers": {"Cookie": "u=B"}},
]


def test_object_endpoint_selection():
    from owlforge.engine.accesscontrol import _object_endpoints
    urls = {t["url"] for t in _object_endpoints(INV)}
    assert "https://t/catalog?productId=1" in urls  # OBJECT_ID param
    assert "https://t/my-account" in urls           # account path
    assert "https://t/orders/123" in urls           # numeric path segment
    assert "https://t/about" not in urls            # plain page excluded


def test_multi_identity_flags_idor_and_missing_authn_not_public(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.accesscontrol import access_control_scan
    from owlforge.store.models import Finding
    n = access_control_scan("a1", INV, _SB(), {}, IDS)
    with db.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "a1")).all()
    eps = {f.endpoint for f in rows}
    assert "https://t/orders/123" in eps            # IDOR: bob reads alice's protected order
    assert "https://t/my-account" in eps            # missing authn: anon reads account page
    assert "https://t/catalog?productId=1" not in eps  # public -> NOT flagged (no false positive)
    assert "https://t/orders/999" not in eps        # boundary held -> NOT flagged
    assert n == 2
    assert all(f.status == "validated" for f in rows)


def test_single_session_only_flags_anon_readable_account(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from sqlmodel import select

    from owlforge.engine.accesscontrol import access_control_scan
    from owlforge.store.models import Finding
    # no identity set, just one authenticated session -> can only catch missing-authn
    n = access_control_scan("a2", INV, _SB(), {"Cookie": "u=A"}, None)
    with db.session() as s:
        eps = {f.endpoint for f in s.exec(select(Finding).where(Finding.assessment_id == "a2")).all()}
    assert "https://t/my-account" in eps            # anon-readable account page
    assert "https://t/orders/123" not in eps        # needs a 2nd identity to prove IDOR
    assert n == 1


def test_noop_without_auth(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.accesscontrol import access_control_scan
    assert access_control_scan("a3", INV, _SB(), {}, None) == 0   # no session, no identities
    assert access_control_scan("a4", INV, None, {}, IDS) == 0     # no sandbox
