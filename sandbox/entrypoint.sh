#!/usr/bin/env bash
# owlforge-sandbox entrypoint. Deliberately does NOT use `set -e` — a non-fatal
# setup failure must never take the container down (the legacy image's #1 bug).
set -u

PORT="${OWLFORGE_AGENTD_PORT:-47130}"

echo "[owlforge-sandbox] starting owlforge-agentd on 0.0.0.0:${PORT}"
# TODO(Phase 2): start mitmproxy here (background) before the daemon.
exec /opt/owlforge/venv/bin/uvicorn agentd.main:app \
    --app-dir /opt/owlforge \
    --host 0.0.0.0 --port "${PORT}"
