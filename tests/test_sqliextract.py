"""Native SQLi value extraction: error-based + boolean-blind ladders, read-only."""
from __future__ import annotations

import re

from owlforge.engine.sqliextract import _W, extract_one, extract_sqli_values


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _PG:
    """Postgres-ish app: a wrapped CAST expression leaks the value in a 500 error body."""
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        blob = str(params) + str(body)
        if "cast(" in blob and "version()" in blob and _W in blob:
            val = "PostgreSQL 14.3/app_user"
            return {"status": 500,
                    "body": f'ERROR: invalid input syntax for integer: "{_W}{val}{_W}"'}
        return {"status": 200, "body": "ok"}


class _Blind:
    """No errors, no echo — only a boolean oracle (true=long body, false=short)."""
    VER = "PG9"

    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "") if params else (body or "")
        return {"status": 200, "body": "x" * 80 if self._truth(v) else "x" * 16}

    def _truth(self, blob: str) -> bool:
        if "1=1" in blob:
            return True
        if "1=2" in blob:
            return False
        m = re.search(r"length\(\(select version\(\)\)\)>=(\d+)", blob)
        if m:
            return len(self.VER) >= int(m.group(1))
        m = re.search(r"ascii\(substring\(\(select version\(\)\),(\d+),1\)\)>(\d+)", blob)
        if m:
            i, n = int(m.group(1)), int(m.group(2))
            return i - 1 < len(self.VER) and ord(self.VER[i - 1]) > n
        return False


class _Union:
    """UNION-based: a 3-column table; wrong column counts 500, and the wrapped value echoes
    only once it is placed in a column (NULLs fill the rest, no type mismatch)."""
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "") if params else (body or "")
        if "UNION SELECT" in v:
            cols = v.split("UNION SELECT", 1)[1].split("--", 1)[0]
            if len([c for c in cols.split(",")]) != 3:
                return {"status": 500, "body": "ERROR: each UNION query must have the same number of columns"}
            if "version()" in v:
                return {"status": 200, "body": f"<li>{_W}FakeDB 1.0/dbuser{_W}</li>"}
            return {"status": 200, "body": "<li>catalog</li>"}
        return {"status": 200, "body": "catalog"}


class _Safe:
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        return {"status": 200, "body": "nothing interesting"}


T = {"url": "https://t/cat", "param": "id", "method": "GET"}


def test_error_based_extracts_value():
    val, how = extract_one(_PG(), T)
    assert val == "PostgreSQL 14.3/app_user"
    assert "error-based" in how


def test_union_based_extracts_value():
    val, how = extract_one(_Union(), T)
    assert val == "FakeDB 1.0/dbuser" and "union-based" in how


def test_boolean_blind_extracts_version():
    val, how = extract_one(_Blind(), T)
    assert val == "PG9" and how.startswith("boolean-blind")


def test_not_injectable_returns_nothing():
    val, how = extract_one(_Safe(), T)
    assert val is None and how == ""


def test_enriches_existing_finding(tmp_path, monkeypatch):
    import secrets

    from owlforge.store.db import session
    from owlforge.store.models import Finding
    db = _db(tmp_path, monkeypatch)
    fid = f"find_{secrets.token_hex(4)}"
    with session() as s:
        s.add(Finding(id=fid, assessment_id="a", title="SQL injection (error-based)",
                      status="candidate", repro_url="https://t/cat", repro_method="GET",
                      repro_params={"id": "1"}))
        s.commit()
    assert extract_sqli_values("a", _PG()) == 1
    with db.session() as s:
        f = s.get(Finding, fid)
    assert f.status == "validated" and f.confidence == "high"
    assert "PostgreSQL 14.3/app_user" in f.proof_of_concept
    assert "value-extracted" in (f.validation_note or "")
