"""`owlforge doctor` preflight."""
from __future__ import annotations

from typer.testing import CliRunner

import owlforge.sandbox.manager as mgr
from owlforge.cli import app


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import owlforge.config as config
    config.load_config.cache_clear()


def test_doctor_all_good(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr(mgr, "container_engine", lambda: "podman")
    monkeypatch.setattr(mgr, "engine_version", lambda e=None: "5.0.0")
    monkeypatch.setattr(mgr, "docker_available", lambda: True)
    monkeypatch.setattr(mgr, "image_exists", lambda i: True)
    r = CliRunner().invoke(app, ["doctor"])
    assert r.exit_code == 0
    assert "owlforge doctor" in r.stdout
    assert "podman" in r.stdout and "running" in r.stdout
    assert "Sandbox image" in r.stdout


def test_doctor_engine_not_running_fails(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr(mgr, "container_engine", lambda: "podman")
    monkeypatch.setattr(mgr, "engine_version", lambda e=None: "5.0.0")
    monkeypatch.setattr(mgr, "docker_available", lambda: False)   # installed, not running
    r = CliRunner().invoke(app, ["doctor"])
    assert r.exit_code == 1
    assert "not running" in r.stdout and "podman machine" in r.stdout


def test_doctor_engine_missing_fails(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr(mgr, "container_engine", lambda: "docker")
    monkeypatch.setattr(mgr, "engine_version", lambda e=None: None)   # not installed
    monkeypatch.setattr(mgr, "docker_available", lambda: False)
    r = CliRunner().invoke(app, ["doctor"])
    assert r.exit_code == 1
    assert "not found" in r.stdout
