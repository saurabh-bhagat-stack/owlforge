"""GraphQL field-argument injection validator: SQLi (marker in DB error), SSTI, LFI; no FPs."""
from __future__ import annotations

import json
import re
import urllib.parse

from owlforge.engine.graphqlinject import graphql_inject_scan

_STR = {"kind": "SCALAR", "name": "String", "ofType": None}


def _field(name):
    return {"name": name, "type": _STR, "args": [{"name": "q", "type": _STR}]}


_INTRO = {"data": {"__schema": {
    "queryType": {"fields": [_field("searchSqli"), _field("renderTpl"), _field("readFile"),
                             _field("safe")]},
    "mutationType": None}}}


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
        return list(s.exec(select(Finding)))


def _qval(method, url, body):
    q = (json.loads(body).get("query", "") if method == "POST" and body
         else urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("query", [""])[0])
    m = re.search(r'(\w+)\(q:\s*"([^"]*)"\)', q)
    return (m.group(1), m.group(2)) if m else (None, None)


class _InjApp:
    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if urllib.parse.urlsplit(url).path != "/graphql":
            return {"status": 404, "body": "nf"}
        q = (json.loads(body).get("query", "") if method == "POST" and body
             else urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("query", [""])[0])
        if "__schema" in q:
            return {"status": 200, "body": json.dumps(_INTRO)}
        field, val = _qval(method, url, body)
        if field == "searchSqli":                       # raw concat into SQL -> error echoes value
            if "'" in val:
                return {"status": 200, "body": json.dumps(
                    {"data": None, "errors": [{"message": f'syntax error at or near "{val}"'}]})}
            return {"status": 200, "body": json.dumps({"data": {"searchSqli": "ok"}})}
        if field == "renderTpl":                         # template engine evaluates the arg
            out = "1787569" if "1337*1337" in val else val
            return {"status": 200, "body": json.dumps({"data": {"renderTpl": out}})}
        if field == "readFile":                          # path traversal -> file contents
            out = "root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in val else "not found"
            return {"status": 200, "body": json.dumps({"data": {"readFile": out}})}
        return {"status": 200, "body": json.dumps({"data": {"safe": "clean"}})}


class _SafeApp:
    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if urllib.parse.urlsplit(url).path != "/graphql":
            return {"status": 404, "body": "nf"}
        q = (json.loads(body).get("query", "") if method == "POST" and body
             else urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("query", [""])[0])
        if "__schema" in q:
            return {"status": 200, "body": json.dumps(_INTRO)}
        return {"status": 200, "body": json.dumps({"data": {"x": "clean"}})}


def test_confirms_sqli_ssti_lfi_via_graphql_args(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = graphql_inject_scan("a", [{"url": "https://t/graphql", "source": "graphql"}], _InjApp(),
                            {}, target="https://t/")
    titles = {f.title for f in _findings(db)}
    assert n >= 3
    assert any("SQL injection" in t for t in titles)
    assert any("template injection" in t for t in titles)
    assert any("Path traversal" in t for t in titles)


def test_no_false_positive_on_safe_app(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    assert graphql_inject_scan("a", [{"url": "https://t/graphql", "source": "graphql"}],
                               _SafeApp(), {}, target="https://t/") == 0
    assert _findings(db) == []
