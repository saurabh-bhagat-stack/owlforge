# owlforge-sandbox — our own disposable execution environment.
# Phase 0: a minimal, buildable skeleton. The tool suite (nmap/httpx/nuclei/ffuf/
# sqlmap/curl) and mitmproxy are added in Phase 2 — intentionally NOT here yet, so
# the image stays tiny while we build the engine.

FROM debian:12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- owlforge-agentd (the in-container control daemon) ---
WORKDIR /opt/owlforge
COPY agentd/requirements.txt /opt/owlforge/agentd/requirements.txt
RUN python3 -m venv /opt/owlforge/venv \
    && /opt/owlforge/venv/bin/pip install -r /opt/owlforge/agentd/requirements.txt
COPY agentd /opt/owlforge/agentd
COPY entrypoint.sh /opt/owlforge/entrypoint.sh
RUN chmod +x /opt/owlforge/entrypoint.sh

# TODO(Phase 2): install the offensive tool suite + mitmproxy here.

EXPOSE 47130
ENTRYPOINT ["/opt/owlforge/entrypoint.sh"]
