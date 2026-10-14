# owlforge-sandbox — our own disposable execution environment.
# debian-slim + a lean recon toolset + owlforge-agentd. No set-e death trap.
# ProjectDiscovery tools (httpx/nuclei/ffuf) + mitmproxy are added in a later pass.

FROM debian:12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    OWLFORGE_WORKSPACE=/workspace

# Recon toolset (apt, reliable + small) + python for the daemon.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl wget \
        nmap dnsutils iputils-ping net-tools \
        jq openssl \
        python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

# owlforge-agentd (isolated venv so apt-managed python stays clean).
WORKDIR /opt/owlforge
COPY agentd/requirements.txt /opt/owlforge/agentd/requirements.txt
RUN python3 -m venv /opt/owlforge/venv \
    && /opt/owlforge/venv/bin/pip install -r /opt/owlforge/agentd/requirements.txt
COPY agentd /opt/owlforge/agentd
COPY entrypoint.sh /opt/owlforge/entrypoint.sh
RUN chmod +x /opt/owlforge/entrypoint.sh

RUN mkdir -p /workspace
EXPOSE 47130
ENTRYPOINT ["/opt/owlforge/entrypoint.sh"]
