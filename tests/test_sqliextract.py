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
    """Postgres-ish app: a wrapped CAST expression leaks the EVALUATED value (delimited by
    _W) in a 500 error body. The payload carries a chr()-built delimiter, not a literal _W."""
    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        blob = str(params) + str(body)
        if "cast(" in blob and "chr(" in blob:
            val = "PostgreSQL 14.3/app_user"
            return {"status": 500,
                    "body": f'ERROR: invalid input syntax for integer: "{_W}{val}{_W}"'}
        return {"status": 200, "body": "ok"}


class _Blind:
    """No errors, no echo — only a content oracle (true=long body, false=short), value in
    version()."""
    VER = "PG9"

    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "") if params else (body or "")
        return {"status": 200, "body": "x" * 80 if self._truth(v) else "x" * 16}

    def _truth(self, blob: str) -> bool:
        if "1=1" in blob:
            return True
        if "1=2" in blob:
            return False
        m = re.search(r"length\(\(version\(\)\)\)>=(\d+)", blob)
        if m:
            return len(self.VER) >= int(m.group(1))
        m = re.search(r"ascii\(substring\(\(version\(\)\),(\d+),1\)\)>(\d+)", blob)
        if m:
            i, n = int(m.group(1)), int(m.group(2))
            return i - 1 < len(self.VER) and ord(self.VER[i - 1]) > n
        return False


class _CondBlind:
    """Models the live ginandjuice case: a STATUS oracle (true=200, false=500) AND a keyword
    filter that strips 'version'/'database' (→ malformed SQL → 500), so extraction must fall
    through to current_user."""
    USER = "app_user"

    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        v = next(iter((params or {}).values()), "") if params else (body or "")
        if "version" in v or "database" in v:        # filtered keyword -> malformed -> error
            return {"status": 500, "body": "err"}
        ok = self._truth(v)
        return {"status": 200 if ok else 500, "body": "ok" if ok else "err"}

    def _truth(self, blob: str) -> bool:
        if "1=1" in blob:
            return True
        if "1=2" in blob or "2=1" in blob:
            return False
        m = re.search(r"length\(\(current_user\)\)>=(\d+)", blob)
        if m:
            return len(self.USER) >= int(m.group(1))
        m = re.search(r"ascii\(substring\(\(current_user\),(\d+),1\)\)>(\d+)", blob)
        if m:
            i, n = int(m.group(1)), int(m.group(2))
            return i - 1 < len(self.USER) and ord(self.USER[i - 1]) > n
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
    assert "via version" in how


def test_conditional_error_falls_through_filter_to_current_user():
    # version()/database() are filtered; extraction must still succeed via current_user
    val, how = extract_one(_CondBlind(), T)
    assert val == "app_user"
    assert "conditional error" in how and "current_user" in how


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


class _MSSQL:
    """MSSQL app, content oracle; value in system_user. length() is invalid in MSSQL (it is LEN),
    so a length()-based probe fails and extraction must fall back to LEN() to recover the value."""
    USER = "sa_dbo"

    def http_request(self, method, url, *, params=None, body=None, headers=None, timeout_ms=30_000):
        blob = next(iter((params or {}).values()), "") if params else (body or "")
        return {"status": 200, "body": "x" * 80 if self._truth(blob) else "x" * 16}

    def _truth(self, blob: str) -> bool:
        if "length(" in blob:                    # invalid on MSSQL -> errors -> not "true"
            return False
        if "case when" not in blob and "1=1" in blob:
            return True
        if "case when" not in blob and "1=2" in blob:
            return False
        m = re.search(r"len\(\(system_user\)\)>=(\d+)", blob)
        if m:
            return len(self.USER) >= int(m.group(1))
        m = re.search(r"ascii\(substring\(\(system_user\),(\d+),1\)\)>(\d+)", blob)
        if m:
            i, n = int(m.group(1)), int(m.group(2))
            return i - 1 < len(self.USER) and ord(self.USER[i - 1]) > n
        return False


def test_extract_mssql_via_len():
    val, how = extract_one(_MSSQL(), {"url": "http://t/x", "param": "id", "method": "GET"})
    assert val == "sa_dbo"
    assert "mssql_user" in how          # recovered via LEN(system_user), not length()
