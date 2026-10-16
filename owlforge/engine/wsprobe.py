"""WebSocket testing pass — exercise discovered WS/SignalR endpoints.

Connects to each WS endpoint, sends benign + marker/payload messages, and flags it as
an injection surface when the server echoes client input back (a classic WS XSS / data
sink). Bounded; deeper WS fuzzing is specialist work guided by the ws playbook.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable


def ws_scan(assessment_id: str, inventory: list[dict], sandbox,
            session_headers: dict | None = None, cap: int = 5,
            log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None or not hasattr(sandbox, "ws_probe"):
        return 0
    from owlforge.store.db import session
    from owlforge.store.models import Finding

    ws_items = [it for it in inventory if it.get("source") == "websocket"]
    filed = 0
    done = 0
    for it in ws_items:
        if done >= cap:
            break
        done += 1
        url = it["url"]
        token = "owlws" + secrets.token_hex(4)
        msgs = [token,
                '{"message":"' + token + '"}',
                '{"type":"message","content":"' + token + "<img src=x onerror=alert(1)>" + '"}']
        try:
            res = sandbox.ws_probe(url, messages=msgs, headers=session_headers or None)
        except Exception:
            continue
        if not res.get("connected"):
            continue
        echoed = any(token in str(r) for r in (res.get("responses") or []))
        log(f"ws: connected {url}" + (" (echoes client input)" if echoed else ""))
        if not echoed:
            continue
        with session() as s:
            s.add(Finding(
                id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
                title=f"WebSocket reflects client input: {url}", severity="medium",
                endpoint=url, method="WS",
                technical_analysis=f"The WebSocket endpoint {url} echoes client-supplied input back to "
                                   "clients. If rendered unencoded this is a WS-delivered XSS / injection "
                                   "sink; review message handling and output encoding.",
                proof_of_concept=f"sent marker {token} -> echoed in a server message",
                evidence="; ".join(str(r)[:120] for r in (res.get("responses") or [])[:3]),
                impact="Attacker-controlled WS messages can reach other clients / sinks.",
                remediation="Validate/encode WS message content; authenticate and origin-check the socket.",
                status="candidate", confidence="medium",
                validation_note="WebSocket echo (manual confirm of the sink/context)"))
            s.commit()
        filed += 1
    return filed
