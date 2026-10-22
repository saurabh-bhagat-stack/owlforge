"""Container lifecycle for the owlforge-sandbox image (docker CLI).

Per-assessment, disposable container: bridge network, agentd port published to
127.0.0.1 on a free host port, per-container bearer token, workspace volume mount,
and a health gate before the session is handed back. Our entrypoint has no `set -e`
trap, so we don't need restart/liveness scaffolding.
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
NOVNC_CONTAINER_PORT = 6080
Logger = Callable[[str], None]


@dataclass
class SandboxSession:
    name: str
    container_id: str
    host_port: int
    token: str
    workspace: str
    client: SandboxClient
    novnc_host_port: int = 0

    @property
    def novnc_url(self) -> str:
        if not self.novnc_host_port:
            return ""
        return f"http://127.0.0.1:{self.novnc_host_port}/vnc.html?autoconnect=1&resize=scale"


_ENGINE_CACHE: str | None = None
_ENGINES = ("docker", "podman", "nerdctl")


def container_engine() -> str:
    """The container CLI owlforge shells out to.

    Order: OWLFORGE_CONTAINER_ENGINE if set; else auto-detect a RUNNING engine
    (docker, then podman, then nerdctl); else the first one that is at least installed
    (so the error message is accurate); else 'docker'. Result is cached."""
    global _ENGINE_CACHE
    import os
    import shutil
    env = os.environ.get("OWLFORGE_CONTAINER_ENGINE", "").strip()
    if env:
        return env
    if _ENGINE_CACHE:
        return _ENGINE_CACHE
    for cand in _ENGINES:                     # prefer one that is actually running
        if shutil.which(cand):
            try:
                if subprocess.run([cand, "info"], capture_output=True,
                                  timeout=12).returncode == 0:
                    _ENGINE_CACHE = cand
                    return cand
            except Exception:
                pass
    for cand in _ENGINES:                     # else: installed-but-not-running (clear error)
        if shutil.which(cand):
            _ENGINE_CACHE = cand
            return cand
    _ENGINE_CACHE = "docker"
    return "docker"


def engine_start_hint(engine: str | None = None) -> str:
    """A human hint for starting the detected engine."""
    eng = engine or container_engine()
    if eng == "podman":
        return "start Podman (e.g. `podman machine start`)"
    if eng == "nerdctl":
        return "start your containerd/nerdctl backend"
    return "start Docker (Docker Desktop, colima, or Rancher Desktop)"


def _run(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def docker_available() -> bool:
    try:
        return _run([container_engine(), "info"], timeout=10).returncode == 0
    except Exception:
        return False


def image_exists(image: str) -> bool:
    try:
        return _run([container_engine(), "image", "inspect", image], timeout=15).returncode == 0
    except Exception:
        return False


def build_image(image: str, context_dir: str | Path, log: Logger = print) -> bool:
    log(f"building {image} from {context_dir} (first build pulls debian-slim; a few minutes)")
    proc = subprocess.run([container_engine(), "build", "-t", image, str(context_dir)], text=True)
    return proc.returncode == 0


def local_digest(image: str) -> str | None:
    """The repo digest of the locally-present image (what was pulled). None when the
    image is a LOCAL BUILD (no RepoDigests) or absent -> caller treats None as 'cannot
    compare, do not nudge'."""
    try:
        r = _run([container_engine(), "image", "inspect", image,
                  "--format", "{{range .RepoDigests}}{{.}} {{end}}"], timeout=15)
        if r.returncode != 0:
            return None
        for token in (r.stdout or "").split():
            if "@sha256:" in token:
                return token.split("@", 1)[1]
    except Exception:
        return None
    return None


def remote_digest(image: str) -> str | None:
    """The registry manifest digest for `image` (metadata only, no layer download).
    None if offline / unauthorised / not found."""
    try:
        r = _run([container_engine(), "buildx", "imagetools", "inspect", image], timeout=25)
        if r.returncode == 0:
            for line in (r.stdout or "").splitlines():
                ls = line.strip()
                if ls.lower().startswith("digest:"):
                    return ls.split(":", 1)[1].strip()
    except Exception:
        pass
    try:
        import json as _json
        r = _run([container_engine(), "manifest", "inspect", "-v", image], timeout=25)
        if r.returncode == 0:
            data = _json.loads(r.stdout or "null")
            if isinstance(data, dict):
                d = (data.get("Descriptor") or {}).get("digest")
                if d:
                    return d
            elif isinstance(data, list) and data:
                d = (data[0].get("Descriptor") or {}).get("digest")
                if d:
                    return d
    except Exception:
        pass
    return None


def update_available(image: str) -> bool | None:
    """True if the registry has a newer image than the local copy; False if up to date;
    None if undeterminable (local build, offline, registry error) -> caller skips."""
    local = local_digest(image)
    if local is None:
        return None
    remote = remote_digest(image)
    if remote is None:
        return None
    return local != remote


def pull_image(image: str, log: Logger = print) -> bool:
    log(f"pulling {image} ...")
    proc = subprocess.run([container_engine(), "pull", image], text=True)
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
    novnc_port = _free_port()
    Path(workspace).mkdir(parents=True, exist_ok=True)

    _run([container_engine(), "rm", "-f", name], timeout=20)  # clear any stale container of this name

    args = [
        container_engine(), "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{host_port}:{AGENTD_CONTAINER_PORT}",
        "-p", f"127.0.0.1:{novnc_port}:{NOVNC_CONTAINER_PORT}",
        "--add-host", "host.docker.internal:host-gateway",
        "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "-e", f"OWLFORGE_AGENTD_TOKEN={token}",
        "-e", f"OWLFORGE_AGENTD_PORT={AGENTD_CONTAINER_PORT}",
        "-e", f"OWLFORGE_NOVNC_PORT={NOVNC_CONTAINER_PORT}",
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
            return SandboxSession(name, container_id, host_port, token, workspace, client,
                                  novnc_host_port=novnc_port)
        time.sleep(1.0)

    logs = _run([container_engine(), "logs", "--tail", "40", name], timeout=15).stdout
    _run([container_engine(), "rm", "-f", name], timeout=20)
    raise RuntimeError(f"sandbox {name} never became healthy. Container logs:\n{logs[:1500]}")


def stop(session: SandboxSession, log: Logger = print) -> None:
    try:
        _run([container_engine(), "rm", "-f", session.name], timeout=20)
        log(f"sandbox stopped ({session.name})")
    except Exception as e:
        log(f"sandbox stop warning: {e}")
