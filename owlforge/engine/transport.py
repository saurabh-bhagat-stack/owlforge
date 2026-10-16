"""Transport detection — WebSocket, SignalR, Blazor.

owlforge's core assumes HTTP request/response. Modern apps also push over WebSocket /
SignalR, and Blazor runs over a SignalR circuit (Server) or a WASM bundle (client).
This module detects those from HTML/JS so the engine can surface WS endpoints and flag
Blazor for the (browser/WS) adapters.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

_WS_NEW = re.compile(r"""new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)
_WS_ABS = re.compile(r"""["'`](wss?://[^"'`\s]+)["'`]""", re.I)
_SIGNALR = re.compile(r"""["'`](/[A-Za-z0-9_\-/]*(?:hub|negotiate)[A-Za-z0-9_\-/]*)["'`]""", re.I)


def detect_transport(base_url: str, text: str) -> tuple[set[str], set[str]]:
    """Return (ws_endpoints, flags). ws_endpoints are absolute ws(s)://… or SignalR URLs;
    flags ⊆ {websocket, signalr, blazor-server, blazor-wasm}."""
    text = text or ""
    ws: set[str] = set()
    flags: set[str] = set()

    for m in _WS_NEW.finditer(text):
        ws.add(m.group(1))
    for m in _WS_ABS.finditer(text):
        ws.add(m.group(1))
    for m in _SIGNALR.finditer(text):
        ws.add(urljoin(base_url, m.group(1)))
        flags.add("signalr")

    low = text.lower()
    if "blazor.webassembly" in low or "blazor.boot.json" in low or "_framework/blazor" in low:
        flags.add("blazor-wasm")
    if "blazor.server" in low or "_blazor" in low:
        flags.add("blazor-server")
    if ws or "websocket" in low:
        flags.add("websocket")

    out: set[str] = set()
    for w in ws:
        if w.startswith(("ws://", "wss://")):
            out.add(w)
        elif w.startswith(("http://", "https://")):
            out.add(w)
        elif w.startswith("/"):
            out.add(urljoin(base_url, w))
    return out, flags


def ws_surface_items(ws_endpoints: set[str]) -> list[dict]:
    """WS endpoints as surface items (method 'WS', source 'websocket')."""
    return [{"url": u, "method": "WS", "params": ["message"], "source": "websocket"}
            for u in sorted(ws_endpoints)]
