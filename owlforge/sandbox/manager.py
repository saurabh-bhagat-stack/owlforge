"""Container lifecycle for the owlforge-sandbox image (docker CLI).

Per-assessment, disposable container: bridge network, agentd port published to
127.0.0.1 on a free host port, per-container bearer token, workspace volume mount,
and a health gate before the session is handed back. Our entrypoint has no `set -e`
trap, so we don't need the legacy's restart/liveness scaffolding.
"""

from __future__ import annotations

import secrets
import socket
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from owlforge.sandbox.client import SandboxClient

AGENTD_CONTAINER_PORT = 47130
Logger = Callable[[str], None]


@dataclass
class SandboxSession:
    name: str
    container_id: str
    host_port: int
    token: str
    workspace: str
    client: SandboxClient


def _run(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def docker_available() -> bool:
    try:
        return _run(["docker", "info"], timeout=10).returncode == 0
    except Exception:
        return False


def image_exists(image: str) -> bool:
    try:
        return _run(["docker", "image", "inspect", image], timeout=15).returncode == 0
    except Exception:
        return False


def build_image(image: str, context_dir: str | Path, log: Logger = print) -> bool:
    log(f"building {image} from {context_dir} (first build pulls debian-slim; a few minutes)")
    proc = subprocess.run(["docker", "build", "-t", image, str(context_dir)], text=True)
    return proc.returncode == 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(
    image: str,
    *,
    name: str | None = None,
    workspace: str,
    log: Logger = print,
    health_timeout: float = 40.0,
) -> SandboxSession:
    name = name or f"owlforge-{secrets.token_hex(4)}"
    token = secrets.token_hex(16)
    host_port = _free_port()
    Path(workspace).mkdir(parents=True, exist_ok=True)

    _run(["docker", "rm", "-f", name], timeout=20)  # clear any stale container of this name

    args = [
        "docker", "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{host_port}:{AGENTD_CONTAINER_PORT}",
        "--add-host", "host.docker.internal:host-gateway",
        "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "-e", f"OWLFORGE_AGENTD_TOKEN={token}",
        "-e", f"OWLFORGE_AGENTD_PORT={AGENTD_CONTAINER_PORT}",
        "-e", "OWLFORGE_WORKSPACE=/workspace",
        "-v", f"{workspace}:/workspace",
        image, 
    ]
    log(f"docker run {name} (port 127.0.0.1:{host_port} -> {AGENTD_CONTAINER_PORT})")
    proc = _run(args, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"docker run failed: {proc.stderr.strip()[:400]}")
    container_id = proc.stdout.strip()

    client = SandboxClient(base_url=f"http://127.0.0.1:{host_port}", token=token)
    deadline = time.monotonic() + health_timeout
    while time.monotonic() < deadline:
        if client.health():
            log(f"sandbox healthy ({name}, {container_id[:12]})")
            return SandboxSession(name, container_id, host_port, token, workspace, client)
        time.sleep(1.0)

    logs = _run(["docker", "logs", "--tail", "40", name], timeout=15).stdout
    _run(["docker", "rm", "-f", name], timeout=20)
    raise RuntimeError(f"sandbox {name} never became healthy. Container logs:\n{logs[:1500]}")


def stop(session: SandboxSession, log: Logger = print) -> None:
    try:
        _run(["docker", "rm", "-f", session.name], timeout=20)
        log(f"sandbox stopped ({session.name})")
    except Exception as e:
        log(f"sandbox stop warning: {e}")
