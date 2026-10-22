"""Sandbox image freshness check: digest parsing + update_available."""
from __future__ import annotations

from types import SimpleNamespace

import owlforge.sandbox.manager as mgr


def _patch(monkeypatch, *, local_stdout="", local_rc=0, remote_stdout="", remote_rc=0):
    def fake_run(args, timeout=60.0):
        if args[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=local_rc, stdout=local_stdout, stderr="")
        if args[:3] == ["docker", "buildx", "imagetools"]:
            return SimpleNamespace(returncode=remote_rc, stdout=remote_stdout, stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")
    monkeypatch.setattr(mgr, "_run", fake_run)


def test_local_digest_parsed(monkeypatch):
    _patch(monkeypatch, local_stdout="ghcr.io/x/owlforge-sandbox@sha256:aaa ")
    assert mgr.local_digest("img") == "sha256:aaa"


def test_local_build_has_no_repo_digest(monkeypatch):
    _patch(monkeypatch, local_stdout="")      # local build -> no RepoDigests
    assert mgr.local_digest("img") is None


def test_remote_digest_from_imagetools(monkeypatch):
    _patch(monkeypatch, remote_stdout="Name: img\nDigest: sha256:bbb\nMediaType: ...\n")
    assert mgr.remote_digest("img") == "sha256:bbb"


def test_update_available_true_when_digests_differ(monkeypatch):
    _patch(monkeypatch, local_stdout="img@sha256:aaa ",
           remote_stdout="Digest: sha256:bbb\n")
    assert mgr.update_available("img") is True


def test_update_available_false_when_same(monkeypatch):
    _patch(monkeypatch, local_stdout="img@sha256:aaa ",
           remote_stdout="Digest: sha256:aaa\n")
    assert mgr.update_available("img") is False


def test_update_available_none_for_local_build(monkeypatch):
    _patch(monkeypatch, local_stdout="", remote_stdout="Digest: sha256:bbb\n")
    assert mgr.update_available("img") is None       # can't compare -> skip (no nudge)


def test_update_available_none_when_registry_unreachable(monkeypatch):
    _patch(monkeypatch, local_stdout="img@sha256:aaa ", remote_rc=1, remote_stdout="")
    assert mgr.update_available("img") is None
