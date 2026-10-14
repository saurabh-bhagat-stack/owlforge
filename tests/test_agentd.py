"""Unit tests for owlforge-agentd (the in-container daemon), via FastAPI TestClient.

agentd ships inside the sandbox image; we import it from the repo's sandbox/ dir.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

SANDBOX = pathlib.Path(__file__).resolve().parents[1] / "sandbox"
sys.path.insert(0, str(SANDBOX))

fastapi = pytest.importorskip("fastapi")
from agentd.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)


def test_health_no_auth():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_exec_captures_exit_and_stdout():
    r = client.post("/exec", json={"command": "echo hello && exit 3", "workdir": "."})
    assert r.status_code == 200
    d = r.json()
    assert d["exit_code"] == 3
    assert "hello" in d["stdout"]


def test_exec_timeout():
    r = client.post("/exec", json={"command": "sleep 5", "timeout_ms": 300, "workdir": "."})
    d = r.json()
    assert d["timed_out"] is True and d["exit_code"] == 124
