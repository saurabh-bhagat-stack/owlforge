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
RUN set -u; ARCH="$(dpkg --print-architecture)"; cd /tmp; \
    ( curl -fsSL -o httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" \
        && unzip -o httpx.zip httpx -d /usr/local/bin && chmod +x /usr/local/bin/httpx ) || echo "WARN: httpx install failed"; \
    ( curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
        && unzip -o nuclei.zip nuclei -d /usr/local/bin && chmod +x /usr/local/bin/nuclei ) || echo "WARN: nuclei install failed"; \
    ( curl -fsSL -o ffuf.tgz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz" \
        && tar -xzf ffuf.tgz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf ) || echo "WARN: ffuf install failed"; \
    rm -f /tmp/*.zip /tmp/*.tgz

# mitmproxy (own venv — heavy deps kept out of the agentd venv).
RUN python3 -m venv /opt/owlforge/mitm-venv \
    && /opt/owlforge/mitm-venv/bin/pip install "mitmproxy>=11,<13"

# owlforge-agentd (its own venv).
WORKDIR /opt/owlforge
COPY agentd/requirements.txt /opt/owlforge/agentd/requirements.txt
RUN python3 -m venv /opt/owlforge/venv \
    && /opt/owlforge/venv/bin/pip install -r /opt/owlforge/agentd/requirements.txt
COPY agentd /opt/owlforge/agentd
RUN /opt/owlforge/venv/bin/playwright install --with-deps chromium
COPY mitm /opt/owlforge/mitm-addons
COPY entrypoint.sh /opt/owlforge/entrypoint.sh
RUN chmod +x /opt/owlforge/entrypoint.sh && mkdir -p /workspace

COPY wordlists /opt/owlforge/wordlists
EXPOSE 47130 6080
ENTRYPOINT ["/opt/owlforge/entrypoint.sh"]
