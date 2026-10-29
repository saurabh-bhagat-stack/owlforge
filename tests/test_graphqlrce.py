"""GraphQL OS command-injection validator: confirm execution via a computed marker, no FPs."""
from __future__ import annotations

import json
import re
import urllib.parse

from owlforge.engine.graphqlrce import _in_data, _unwrap, graphql_rce_scan

_STR = {"kind": "SCALAR", "name": "String", "ofType": None}
_INTRO = {"data": {"__schema": {
    "queryType": {"fields": [
        {"name": "getCommandResult", "type": _STR,
         "args": [{"name": "command", "type": _STR}]},
        {"name": "hello", "type": _STR, "args": []}]},
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


def _query_of(method, url, body):
    if method == "POST" and body:
        try:
            return json.loads(body).get("query", "")
        except Exception:
            return ""
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("query", [""])[0]


class _ExecFileApp:
    """A command sink that runs the first token as a binary (execFile): `expr A * B` computes,
    `echo X` prints X — i.e. a real RCE, like brokencrystals' getCommandResult."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if urllib.parse.urlsplit(url).path != "/graphql":
            return {"status": 404, "body": "not found"}
        q = _query_of(method, url, body)
        if "__schema" in q:
            return {"status": 200, "body": json.dumps(_INTRO)}
        m = re.search(r'getCommandResult\(command:\s*"([^"]*)"\)', q)
        if not m:
            return {"status": 200, "body": json.dumps({"data": None, "errors": [{"message": "x"}]})}
        cmd = m.group(1).strip()
        em = re.match(r"expr\s+(\d+)\s*\*\s*(\d+)$", cmd)
        out = str(int(em.group(1)) * int(em.group(2))) if em else (
            cmd[5:] if cmd.startswith("echo ") else cmd)
        return {"status": 200, "body": json.dumps({"data": {"getCommandResult": out + "\n"}})}


class _ReflectApp:
    """A sink that only REFLECTS the command back in an error (no execution) — must NOT confirm."""

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        if urllib.parse.urlsplit(url).path != "/graphql":
            return {"status": 404, "body": "not found"}
        q = _query_of(method, url, body)
        if "__schema" in q:
            return {"status": 200, "body": json.dumps(_INTRO)}
        return {"status": 200, "body": json.dumps(
            {"data": None, "errors": [{"message": f"cannot run: {q}"}]})}


def test_in_data_ignores_reflection_in_errors():
    assert _in_data(json.dumps({"data": {"r": "12345678\n"}}), "12345678")
    assert not _in_data(json.dumps({"data": None, "errors": [{"message": "12345678"}]}), "12345678")


def test_unwrap_follows_nonnull_and_list():
    t = {"kind": "NON_NULL", "ofType": {"kind": "LIST",
         "ofType": {"kind": "SCALAR", "name": "String"}}}
    assert _unwrap(t) == ("SCALAR", "String")


def test_confirms_rce_on_execfile_sink(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    n = graphql_rce_scan("a", [], _ExecFileApp(), {}, target="https://t/")
    assert n == 1
    f = _findings(db)
    assert len(f) == 1
    assert "command injection" in f[0].title.lower() and f[0].severity == "critical"
    assert f[0].success_signal.isdigit()                 # the computed product


def test_no_false_positive_on_reflection(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    assert graphql_rce_scan("a", [], _ReflectApp(), {}, target="https://t/") == 0
    assert _findings(db) == []
