#!/usr/bin/env bash
# owlforge-sandbox entrypoint. NO `set -e` — a non-fatal hiccup must never take the
# container down. Best-effort: bring up mitmproxy capture, trust its CA, route tool
# traffic through it; if any step fails, tools simply go direct (uncaptured).
set -u

PORT="${OWLFORGE_AGENTD_PORT:-47130}"
WS="${OWLFORGE_WORKSPACE:-/workspace}"
MITM_PORT="${OWLFORGE_MITM_PORT:-8080}"
MITM_CONFDIR="/opt/owlforge/mitm-conf"
export OWLFORGE_FLOWLOG="${WS}/.owlforge/flows.jsonl"
mkdir -p "${WS}/.owlforge" "${MITM_CONFDIR}"

echo "[owlforge-sandbox] starting mitmproxy capture on :${MITM_PORT}"
/opt/owlforge/mitm-venv/bin/mitmdump \
    --set confdir="${MITM_CONFDIR}" \
    -s /opt/owlforge/mitm-addons/flowlog.py \
    --listen-host 127.0.0.1 --listen-port "${MITM_PORT}" -q &
MITM_PID=$!

# Wait for mitmproxy's CA, then trust it so curl/httpx/nuclei accept intercepted TLS.
CA=""
for _ in $(seq 1 15); do
    if [ -f "${MITM_CONFDIR}/mitmproxy-ca-cert.pem" ]; then
        CA="${MITM_CONFDIR}/mitmproxy-ca-cert.pem"; break
    fi
    sleep 0.5
done
PROXY_UP=0
if [ -n "${CA}" ]; then
    cp "${CA}" /usr/local/share/ca-certificates/mitmproxy.crt 2>/dev/null \
        && update-ca-certificates >/dev/null 2>&1 \
        && echo "[owlforge-sandbox] mitmproxy CA trusted"
    # Confirm the proxy port is actually accepting.
    for _ in $(seq 1 15); do
        if curl -s -x "http://127.0.0.1:${MITM_PORT}" -o /dev/null --max-time 2 http://127.0.0.1/ 2>/dev/null; then
            PROXY_UP=1; break
        fi
        sleep 0.5
    done
fi

if [ "${PROXY_UP}" = "1" ]; then
    export http_proxy="http://127.0.0.1:${MITM_PORT}"
    export https_proxy="http://127.0.0.1:${MITM_PORT}"
    export HTTP_PROXY="${http_proxy}" HTTPS_PROXY="${https_proxy}"
    echo "[owlforge-sandbox] tool traffic routes through mitmproxy (captured)"
else
    echo "[owlforge-sandbox] mitmproxy not ready — tools will connect directly (uncaptured)"
    kill "${MITM_PID}" 2>/dev/null || true
fi

echo "[owlforge-sandbox] owlforge-agentd on 0.0.0.0:${PORT} (workspace=${WS})"
exec /opt/owlforge/venv/bin/uvicorn agentd.main:app \
    --app-dir /opt/owlforge --host 0.0.0.0 --port "${PORT}"
