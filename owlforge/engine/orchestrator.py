"""Orchestrator (attack planner) — reads the blackboard (surface inventory), plans
deterministic per-class tasks, and dispatches focused specialist agents.

Planning is deterministic (reliable); each specialist is a narrow run_single_agent
(better local-model performance than one agent doing everything). All specialists
share the assessment, so findings accumulate for a single validation + report pass.
"""

from __future__ import annotations

from collections import defaultdict

from sqlmodel import select

from owlforge.engine.agent import run_single_agent
from owlforge.engine.classify import (
    CSRF,
    OBJECT_ID,
    PATH,
    SQLI,
    SSRF,
    XSS,
    classify_param,
    endpoint_interesting,
)
from owlforge.engine.events import Emitter
from owlforge.engine.preprobe import GATEABLE, filter_targets
from owlforge.store.db import session
from owlforge.store.models import SurfaceItem
from owlforge.tools.builtin import build_registry

_TITLE = {
    SQLI: "SQL injection",
    XSS: "reflected cross-site scripting",
    PATH: "path traversal / local file inclusion",
    OBJECT_ID: "broken access control / IDOR",
    SSRF: "SSRF / open redirect",
    CSRF: "cross-site request forgery",
}
_HINT = {
    SQLI: "a lone single quote (') that makes the response error/500 and reverts to 200 when balanced ('')",
    XSS: "a unique marker reflected RAW in the response (NOT HTML-encoded &lt;)",
    PATH: "payloads like ../../../../etc/passwd returning file contents (e.g. root:x:0:0)",
    OBJECT_ID: "accessing another object's id, or a forbidden/hidden endpoint, and receiving data you should not",
    SSRF: "a URL parameter causing a server-side fetch, or an attacker URL reflected in a redirect/Location",
    CSRF: "a state-changing request still succeeds with the anti-CSRF token omitted/replaced, and no "
          "SameSite cookie or Origin/Referer check blocks a cross-site submission",
}
_ORDER = [SQLI, XSS, PATH, OBJECT_ID, SSRF, CSRF]
_MAX_TARGETS = 8  # per specialist — test the highest-interest first, don't dilute budget


def _priority(cls: str, t: dict) -> int:
    """Interest score (spec §3.3): test the most promising targets first."""
    p = (t.get("param") or "").lower()
    url = t["url"].lower()
    if cls in (SQLI, XSS):
        if any(k in p for k in ("category", "filter", "search", "query", "term",
                                "keyword", "sort", "name", "title", "q")):
            return 3  # free-text / filter params — most likely injectable
        if any(k in p for k in ("id", "pid", "productid", "postid", "uid")):
            return 1  # ids are often int-validated (low yield for sqli/xss)
        return 2
    if cls == OBJECT_ID:
        if t.get("param") is None and any(k in url for k in ("admin", "internal", "debug")):
            return 3
        if any(k in p for k in ("id", "pid", "uid", "productid", "postid", "orderid")):
            return 3
        return 1
    return 2


def read_blackboard(assessment_id: str) -> list[dict]:
    with session() as s:
        rows = s.exec(select(SurfaceItem).where(SurfaceItem.assessment_id == assessment_id)).all()
        return [{"url": r.url, "method": r.method, "params": list(r.params or []), "source": r.source} for r in rows]


def plan_tasks(inventory: list[dict]) -> dict[str, list[dict]]:
    tasks: dict[str, list[dict]] = defaultdict(list)
    seen: set[tuple] = set()
    for it in inventory:
        if it["params"]:
            for p in it["params"]:
                for cls in classify_param(p):
                    key = (cls, it["method"], it["url"], p)
                    if key in seen:
                        continue
                    seen.add(key)
                    tasks[cls].append({"url": it["url"], "method": it["method"], "param": p})
        elif endpoint_interesting(it["url"]):
            key = (OBJECT_ID, it["method"], it["url"], None)
            if key not in seen:
                seen.add(key)
                tasks[OBJECT_ID].append({"url": it["url"], "method": it["method"], "param": None})
        if it.get("method", "GET").upper() in ("POST", "PUT", "DELETE", "PATCH"):
            key = (CSRF, it["method"], it["url"], None)
            if key not in seen:
                seen.add(key)
                tasks[CSRF].append({"url": it["url"], "method": it["method"], "param": None})
    return dict(tasks)


def _targets_text(targets: list[dict], limit: int = 30) -> str:
    lines = []
    for t in targets[:limit]:
        p = f"  param={t['param']}" if t.get("param") else ""
        lines.append(f"- {t['method']} {t['url']}{p}")
    if len(targets) > limit:
        lines.append(f"- … and {len(targets) - limit} more")
    return "\n".join(lines)


async def run_orchestrated(
    *,
    assessment_id: str,
    client,
    sandbox,
    emit: Emitter,
    session_headers: dict | None,
    scan_mode: str,
    target: str,
    max_turns: int = 10,
    scope=None,
) -> str:
    inventory = read_blackboard(assessment_id)
    tasks = plan_tasks(inventory)
    total = sum(len(v) for v in tasks.values())
    emit("status", f"orchestrator: {len(inventory)} surface items -> {total} task(s) across {len(tasks)} class(es)")
    registry = build_registry(with_sandbox=sandbox is not None)

    ran: list[str] = []
    for cls in _ORDER:
        targets = tasks.get(cls)
        if not targets:
            continue
        if scope is not None and not scope.allows_class(cls):
            emit("status", f"[specialist:{cls}] skipped (not in --only)")
            continue
        if scope is not None:
            targets = [t for t in targets if scope.in_scope(t["url"])]
            if not targets:
                continue
        targets = sorted(targets, key=lambda t: _priority(cls, t), reverse=True)
        # deterministic pre-probe: only signal-positive targets earn a specialist
        probed, probe_notes = filter_targets(cls, targets[:16], sandbox, session_headers)
        if cls in GATEABLE and not probed:
            emit("status", f"[specialist:{cls}] skipped (pre-probe found no signal)")
            continue
        targets = (probed or targets)[:_MAX_TARGETS]
        emit("status", f"[specialist:{cls}] testing {len(targets)} target(s) (highest-interest first)")
        hint = ("\n\nPre-probe ALREADY observed these signals — confirm and exploit them first:\n- "
                + "\n- ".join(probe_notes[:8])) if probe_notes else ""
        instr = (
            f"You are a {_TITLE[cls]} specialist. Test ONLY for {_TITLE[cls]} on the targets below — "
            f"nothing else. Signal of success: {_HINT[cls]}. Use http_request (put RAW payloads in "
            f"params; do not url-encode); you may also use exec_command (curl, ffuf, nuclei, the sandbox "
            f"toolkit) when a request is filtered. Test each target's parameter. The moment you CONFIRM an issue, "
            "call create_finding with severity, a proof_of_concept, and a STRUCTURED repro: "
            "repro_url (the endpoint), repro_params with the EXACT raw payload value that triggered it, "
            "and success_signal (text present ONLY when vulnerable, e.g. 500). Then call finish. Do not "
            "file what you cannot reproduce." + hint
        )
        try:
            await run_single_agent(
                client=client, registry=registry, emit=emit, assessment_id=assessment_id,
                target=target, instructions=instr, scan_mode=scan_mode, max_turns=max_turns,
                sandbox=sandbox, session_headers=session_headers, surface=_targets_text(targets),
                expected_signal="; ".join(probe_notes[:4]),
            )
        except Exception as e:
            emit("error", f"specialist {cls} crashed: {type(e).__name__}: {e}")
        ran.append(cls)

    return (f"Orchestrated assessment over {len(inventory)} surface items: ran "
            f"{len(ran)} specialist(s) [{', '.join(ran) or 'none'}].")
