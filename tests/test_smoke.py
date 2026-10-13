"""Phase 0 smoke tests: the CLI runs, config defaults load, the store initializes."""

from __future__ import annotations

import importlib

from typer.testing import CliRunner

runner = CliRunner()


def test_version():
    from owlforge import __version__
    from owlforge.cli import app

    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_default_config_loads():
    from owlforge.config import Config

    cfg = Config()
    assert cfg.llm.base_url.startswith("http")
    assert cfg.testing.default_target == "https://ginandjuice.shop/"


def test_init_and_run_use_isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    # Reload config + db modules so they pick up the isolated OWLFORGE_HOME.
    import owlforge.config as config

    importlib.reload(config)
    import owlforge.store.db as db

    importlib.reload(db)
    import owlforge.cli as cli

    importlib.reload(cli)

    assert runner.invoke(cli.app, ["init"]).exit_code == 0
    assert (tmp_path / "owlforge.db").exists()

    r = runner.invoke(cli.app, ["run", "-m", "smoke test", "--project", "t"])
    assert r.exit_code == 0

    r = runner.invoke(cli.app, ["assessments", "list"])
    assert r.exit_code == 0
    assert "asmt_" in r.stdout
