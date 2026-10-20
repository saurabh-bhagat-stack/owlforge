# owlforge-sandbox — our own disposable execution environment.
# debian-slim + recon kit + ProjectDiscovery tools + mitmproxy capture + agentd.
# No `set -e` death trap in the entrypoint.

FROM debian:12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    OWLFORGE_WORKSPACE=/workspace \
    PATH="/usr/local/bin:${PATH}"

# Base recon kit (apt) + python + unzip for fetching Go tool releases.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl wget unzip \
        nmap dnsutils iputils-ping net-tools \
        jq openssl git \
        xvfb x11vnc websockify novnc procps \
        python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery httpx + nuclei + ffuf (arch-aware). Best-effort per tool so a
# release-URL hiccup never breaks the whole image; `sandbox status` reports what landed.
ARG HTTPX_VERSION=1.6.9
ARG NUCLEI_VERSION=3.3.9
ARG FFUF_VERSION=2.1.0
ARG KATANA_VERSION=1.1.0
ARG INTERACTSH_VERSION=1.2.4
RUN set -u; ARCH="$(dpkg --print-architecture)"; cd /tmp; \
    ( curl -fsSL -o httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" \
        && unzip -o httpx.zip httpx -d /usr/local/bin && chmod +x /usr/local/bin/httpx ) || echo "WARN: httpx install failed"; \
    ( curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
        && unzip -o nuclei.zip nuclei -d /usr/local/bin && chmod +x /usr/local/bin/nuclei ) || echo "WARN: nuclei install failed"; \
    ( curl -fsSL -o ffuf.tgz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz" \
        && tar -xzf ffuf.tgz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf ) || echo "WARN: ffuf install failed"; \
    ( curl -fsSL -o katana.zip "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" \
        && unzip -o katana.zip katana -d /usr/local/bin && chmod +x /usr/local/bin/katana ) || echo "WARN: katana install failed"; \
    ( curl -fsSL -o interactsh.zip "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VERSION}/interactsh-client_${INTERACTSH_VERSION}_linux_${ARCH}.zip" \
        && unzip -o interactsh.zip interactsh-client -d /usr/local/bin && chmod +x /usr/local/bin/interactsh-client ) || echo "WARN: interactsh-client install failed"; \
    rm -f /tmp/*.zip /tmp/*.tgz

# mitmproxy (own venv — heavy deps kept out of the agentd venv).
RUN python3 -m venv /opt/owlforge/mitm-venv \
    && /opt/owlforge/mitm-venv/bin/pip install "mitmproxy>=11,<13"

# wafw00f (WAF fingerprinting) in its own venv, symlinked onto PATH.
RUN python3 -m venv /opt/owlforge/recon-venv \
    && /opt/owlforge/recon-venv/bin/pip install wafw00f \
    && ln -sf /opt/owlforge/recon-venv/bin/wafw00f /usr/local/bin/wafw00f

# owlforge-agentd venv + Chromium + nuclei templates FIRST (heavy, rarely change),
# then the agentd code LAST so editing it rebuilds in seconds (no chromium re-download).
WORKDIR /opt/owlforge
COPY agentd/requirements.txt /opt/owlforge/agentd/requirements.txt
RUN python3 -m venv /opt/owlforge/venv \
    && /opt/owlforge/venv/bin/pip install -r /opt/owlforge/agentd/requirements.txt
RUN /opt/owlforge/venv/bin/playwright install --with-deps chromium
# bake nuclei templates (full set) so --nuclei scans are fast + reproducible
RUN nuclei -update-templates -disable-update-check 2>/dev/null || echo "WARN: nuclei template fetch failed"
RUN /opt/owlforge/venv/bin/pip install "websockets>=12"
COPY mitm /opt/owlforge/mitm-addons
COPY wordlists /opt/owlforge/wordlists
COPY entrypoint.sh /opt/owlforge/entrypoint.sh
RUN chmod +x /opt/owlforge/entrypoint.sh && mkdir -p /workspace
COPY agentd /opt/owlforge/agentd
EXPOSE 47130 6080
ENTRYPOINT ["/opt/owlforge/entrypoint.sh"]
