"""Checkpoint persistence + resume command guards."""
from __future__ import annotations

import importlib

from typer.testing import CliRunner

runner = CliRunner()


def _reload(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import owlforge.config as config
    importlib.reload(config)
    import owlforge.store.db as db
    importlib.reload(db)
    db.init_db()
    import owlforge.cli as cli
    importlib.reload(cli)
    return db, cli


def test_progress_field_round_trips(tmp_path, monkeypatch):
    db, _ = _reload(tmp_path, monkeypatch)
    from owlforge.store.models import Assessment
    with db.session() as s:
        s.add(Assessment(id="a", project_name="p", target="t", instructions="x",
                         scan_mode="deep", progress={"done_keys": [["sqli", "https://t/x", "id"]]}))
        s.commit()
    with db.session() as s:
        a = s.get(Assessment, "a")
    assert a.progress["done_keys"] == [["sqli", "https://t/x", "id"]]


def test_resume_unknown_id_errors(tmp_path, monkeypatch):
    _, cli = _reload(tmp_path, monkeypatch)
    r = runner.invoke(cli.app, ["resume", "nope"])
    assert r.exit_code == 1 and "no such assessment" in r.stdout.lower()


def test_resume_completed_is_noop(tmp_path, monkeypatch):
    db, cli = _reload(tmp_path, monkeypatch)
    from owlforge.store.models import Assessment
    with db.session() as s:
        s.add(Assessment(id="done1", project_name="p", target="t", instructions="x",
                         scan_mode="deep", status="completed"))
        s.commit()
    r = runner.invoke(cli.app, ["resume", "done1"])
    assert r.exit_code == 0 and "already completed" in r.stdout.lower()


def test_orchestrator_accepts_seed_and_checkpoint():
    import inspect

    from owlforge.engine.orchestrator import run_orchestrated
    params = inspect.signature(run_orchestrated).parameters
    assert "done_seed" in params and "checkpoint" in params
