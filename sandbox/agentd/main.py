"""owlforge-agentd — minimal Phase 0 daemon.

Exposes /health so the engine can gate on readiness. Phase 2 adds /exec (with a
streaming channel), /files, and /proxy, all behind a per-assessment bearer token.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

app = FastAPI(title="owlforge-agentd", version="0.0.1")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "owlforge-agentd", "version": app.version}


@app.get("/")
def root() -> dict:
    return {"service": "owlforge-agentd", "port": int(os.environ.get("OWLFORGE_AGENTD_PORT", "47130"))}
