"""Container-engine resolution: env override + auto-detect a running engine."""
from __future__ import annotations

from types import SimpleNamespace

import owlforge.sandbox.manager as mgr


def _reset(monkeypatch, *, installed, running):
    monkeypatch.setattr(mgr, "_ENGINE_CACHE", None)
    monkeypatch.delenv("OWLFORGE_CONTAINER_ENGINE", raising=False)
    import shutil
    monkeypatch.setattr(shutil, "which", lambda c: c if c in installed else None)

    def fake_run(args, **kw):
        eng = args[0]
        rc = 0 if (eng in running and args[1:2] == ["info"]) else 1
        return SimpleNamespace(returncode=rc, stdout="", stderr="")
    monkeypatch.setattr(mgr.subprocess, "run", fake_run)


def test_env_override_wins(monkeypatch):
    monkeypatch.setenv("OWLFORGE_CONTAINER_ENGINE", "podman")
    assert mgr.container_engine() == "podman"


def test_prefers_running_docker(monkeypatch):
    _reset(monkeypatch, installed={"docker", "podman"}, running={"docker"})
    assert mgr.container_engine() == "docker"


def test_falls_back_to_running_podman(monkeypatch):
    # docker not installed, podman installed AND running -> podman
    _reset(monkeypatch, installed={"podman"}, running={"podman"})
    assert mgr.container_engine() == "podman"


def test_installed_but_not_running_still_named(monkeypatch):
    # podman installed but machine not started -> still returns podman (for a clear error)
    _reset(monkeypatch, installed={"podman"}, running=set())
    assert mgr.container_engine() == "podman"


def test_nothing_installed_defaults_docker(monkeypatch):
    _reset(monkeypatch, installed=set(), running=set())
    assert mgr.container_engine() == "docker"


def test_start_hint_per_engine():
    assert "podman machine" in mgr.engine_start_hint("podman")
    assert "Docker" in mgr.engine_start_hint("docker")
