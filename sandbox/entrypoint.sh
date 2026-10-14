#!/usr/bin/env bash
# owlforge-sandbox entrypoint. NO `set -e` — a non-fatal hiccup must never take the
# container down (the legacy image's #1 failure). Just launch the daemon and stay up.
set -u

PORT="${OWLFORGE_AGENTD_PORT:-47130}"
echo "[owlforge-sandbox] owlforge-agentd starting on 0.0.0.0:${PORT} (workspace=${OWLFORGE_WORKSPACE:-/workspace})"
# TODO(next): start mitmproxy here (background) before the daemon.
exec /opt/owlforge/venv/bin/uvicorn agentd.main:app \
    --app-dir /opt/owlforge \
    --host 0.0.0.0 --port "${PORT}"
