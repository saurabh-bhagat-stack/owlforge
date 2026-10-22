"""sqlmap read-only confirmation of a detected SQLi."""
from __future__ import annotations

from types import SimpleNamespace

from owlforge.engine.sqlmapconfirm import _target_url


def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


def test_target_url_adds_param():
    assert _target_url("https://t/c", {"category": "x"}) == "https://t/c?category=1"
    assert _target_url("https://t/c?id=5", {}) == "https://t/c?id=5"


class _SB:
    def __init__(self, stdout="", exit_code=0, stderr=""):
        self._o, self._e, self._err = stdout, exit_code, stderr
        self.cmds = []

    def exec(self, command, *, workdir=None, timeout_ms=60000, bypass_proxy=False):
        self.cmds.append(command)
        return SimpleNamespace(stdout=self._o, exit_code=self._e, stderr=self._err)


_OUT = """
[*] starting
sqlmap identified the following injection point
Parameter: category (GET)
    Type: error-based
[*] the parameter 'category' is vulnerable
back-end DBMS: PostgreSQL
current user: 'app_ro'
current database: 'shopdb'
"""


def _seed(db):
    from owlforge.store.models import Finding
    with db.session() as s:
        s.add(Finding(id="sq1", assessment_id="a", title="SQL injection (error-based)",
                      severity="high", status="candidate", endpoint="https://t/catalog",
                      repro_url="https://t/catalog", repro_params={"category": "1'"},
                      technical_analysis="error-based differential"))
        s.commit()


def test_sqlmap_confirms_and_enriches(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from owlforge.engine.sqlmapconfirm import sqlmap_confirm
    sb = _SB(stdout=_OUT)
    assert sqlmap_confirm("a", sb) == 1
    assert "sqlmap -u" in sb.cmds[0] and "--dump" not in sb.cmds[0]  # read-only
    from owlforge.store.models import Finding
    with db.session() as s:
        f = s.get(Finding, "sq1")
    assert f.status == "validated" and f.confidence == "high"
    assert "PostgreSQL" in f.technical_analysis and "app_ro" in f.technical_analysis


def test_sqlmap_missing_tool(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _seed(db)
    from owlforge.engine.sqlmapconfirm import sqlmap_confirm
    assert sqlmap_confirm("a", _SB(stdout="", exit_code=127, stderr="sqlmap: command not found")) == 0


def test_sqlmap_no_sqli_findings(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.sqlmapconfirm import sqlmap_confirm
    assert sqlmap_confirm("a", _SB(stdout=_OUT)) == 0
