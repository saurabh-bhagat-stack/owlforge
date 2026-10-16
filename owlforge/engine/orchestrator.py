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
    CRLF,
    CSRF,
    DESER,
    FILE_UPLOAD,
    GRAPHQL,
    NOSQL,
    OBJECT_ID,
    OPEN_REDIRECT,
    PATH,
    RCE,
    SQLI,
    SSRF,
    SSTI,
    XSS,
    XXE,
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
    SSTI: "server-side template injection",
    RCE: "OS command injection / RCE",
    OPEN_REDIRECT: "open redirect",
    CRLF: "CRLF / HTTP response-header injection",
    NOSQL: "NoSQL injection",
    XXE: "XML external entity (XXE) injection",
    DESER: "insecure deserialization",
    FILE_UPLOAD: "unrestricted file upload (webshell / RCE)",
    GRAPHQL: "GraphQL abuse",
}
_HINT = {
    SQLI: "a lone single quote (') that makes the response error/500 and reverts to 200 when balanced ('')",
    XSS: "a unique marker reflected RAW in the response (NOT HTML-encoded &lt;)",
    PATH: "payloads like ../../../../etc/passwd returning file contents (e.g. root:x:0:0)",
    OBJECT_ID: "accessing another object's id, or a forbidden/hidden endpoint, and receiving data you should not",
    SSRF: "a URL parameter causing a server-side fetch, or an attacker URL reflected in a redirect/Location",
    CSRF: "a state-changing request still succeeds with the anti-CSRF token omitted/replaced, and no "
          "SameSite cookie or Origin/Referer check blocks a cross-site submission",
    SSTI: "a template expression is evaluated server-side (e.g. {{1337*1337}} -> 1787569); escalate to code/file read",
    RCE: "an injected OS command runs (e.g. ;id -> uid=.../gid=...); keep proof read-only (id/hostname)",
    OPEN_REDIRECT: "an attacker URL in the parameter becomes the 3xx Location (off-site redirect)",
    CRLF: "a newline in the parameter injects a new response header (e.g. an extra Set-Cookie)",
    NOSQL: "operator injection (e.g. [$ne]/[$gt] or \'||1==1) changes auth/query behaviour",
    XXE: "an external entity is resolved (file read / SSRF via the XML parser)",
    DESER: "a crafted serialized object is deserialized (gadget -> code/behaviour change)",
    FILE_UPLOAD: "a server-side-executable file (e.g. .php/.jsp) is accepted and then runs when fetched",
    GRAPHQL: "introspection is open, or an argument is injectable / lets you read another object (IDOR)",
}
_ORDER = [RCE, SSTI, SQLI, NOSQL, XSS, PATH, XXE, DESER, FILE_UPLOAD, GRAPHQL,
          OBJECT_ID, SSRF, OPEN_REDIRECT, CRLF, CSRF]
_FILE_PARAM = ("file", "upload", "attachment", "avatar", "document", "photo", "image", "userfile")
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
        u = it["url"].lower()
        if it.get("source") in ("api-spec", "graphql") or any(x in u for x in ("xml", "soap", "wsdl")):
            key = (XXE, it["method"], it["url"], None)
            if key not in seen:
                seen.add(key)
                tasks[XXE].append({"url": it["url"], "method": it["method"], "param": None})
        if it.get("source") == "graphql":
            key = (GRAPHQL, it["method"], it["url"], None)
            if key not in seen:
                seen.add(key)
                tasks[GRAPHQL].append({"url": it["url"], "method": it["method"], "param": "query"})
        if it.get("method", "GET").upper() in ("POST", "PUT"):
            for fp in [p for p in it.get("params", []) if any(f in p.lower() for f in _FILE_PARAM)]:
                key = (FILE_UPLOAD, it["method"], it["url"], fp)
                if key not in seen:
                    seen.add(key)
                    tasks[FILE_UPLOAD].append({"url": it["url"], "method": it["method"], "param": fp})
    return dict(tasks)


def _targets_text(targets: list[dict], limit: int = 30) -> str:
    lines = []
    for t in targets[:limit]:
        p = f"  param={t['param']}" if t.get("param") else ""
        lines.append(f"- {t['method']} {t['url']}{p}")
    if len(targets) > limit:
        lines.append(f"- … and {len(targets) - limit} more")
    return "\n".join(lines)


def _autofile_probe_finding(assessment_id: str, repro: dict) -> None:
    """Deterministically file a finding the pre-probe already CONFIRMED, so recall never
    depends on the LLM remembering to call create_finding. Validation re-tests it."""
    import secrets as _secrets

    from owlforge.store.db import session
    from owlforge.store.models import Finding

    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=repro["title"], severity=repro.get("severity", "medium"),
            endpoint=repro["url"], method=repro.get("method", "GET"),
            technical_analysis=f"A deterministic pre-probe confirmed this at {repro['url']} "
                               f"(param {repro['param']}, payload {repro['payload']!r}).",
            proof_of_concept=f"{repro['param']}={repro['payload']} -> signal '{repro['success_signal']}'",
            evidence=f"param {repro['param']} payload {repro['payload']!r} -> {repro['success_signal']}",
            impact="See the vulnerability class description.",
            remediation="Validate/encode/parameterize the affected input per its class.",
            repro_url=repro["url"], repro_method=repro.get("method", "GET"),
            repro_params={repro["param"]: repro["payload"]}, success_signal=repro["success_signal"],
            status="candidate", confidence="high",
            validation_note="deterministic pre-probe (auto-filed)"))
        s.commit()


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
    max_rounds: int = 2,
) -> str:
    registry = build_registry(with_sandbox=sandbox is not None)
    done_keys: set = set()
    ran: list[str] = []

    for rnd in range(max_rounds):
        inventory = read_blackboard(assessment_id)
        tasks = plan_tasks(inventory)
        if rnd == 0:
            total = sum(len(v) for v in tasks.values())
            emit("status", f"orchestrator: {len(inventory)} surface items -> {total} "
                           f"task(s) across {len(tasks)} class(es)")
        else:
            emit("status", f"orchestrator round {rnd + 1}: {len(inventory)} surface items "
                           "(re-planning on newly-discovered surface)")
        ran_this_round = 0
        for cls in _ORDER:
            targets = tasks.get(cls)
            if not targets:
                continue
            if scope is not None and not scope.allows_class(cls):
                continue
            if scope is not None:
                targets = [t for t in targets if scope.in_scope(t["url"])]
            # drop targets already handled in a previous round
            targets = [t for t in targets if (cls, t["url"], t.get("param")) not in done_keys]
            if not targets:
                continue
            targets = sorted(targets, key=lambda t: _priority(cls, t), reverse=True)
            # deterministic pre-probe: only signal-positive targets earn a specialist
            probed, probe_notes, repros = filter_targets(cls, targets[:16], sandbox, session_headers)
            for _r in repros:
                _autofile_probe_finding(assessment_id, _r)
            if repros:
                emit("status", f"[specialist:{cls}] pre-probe auto-filed {len(repros)} confirmed finding(s)")
            if cls == XSS and rnd == 0:
                from owlforge.engine.domxss import browser_xss_scan
                _bx = browser_xss_scan(assessment_id, targets[:8], sandbox, session_headers,
                                       log=lambda m: emit("status", m))
                if _bx:
                    emit("status", f"[specialist:xss] browser scan auto-filed {_bx} executing XSS")
            if cls in GATEABLE and not probed:
                for t in targets[:16]:
                    done_keys.add((cls, t["url"], t.get("param")))  # don't re-probe dead targets
                if rnd == 0:
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
                f"toolkit) when a request is filtered. Test each target's parameter. The moment you CONFIRM "
                "an issue, call create_finding with severity, a proof_of_concept, and a STRUCTURED repro: "
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
            for t in targets:
                done_keys.add((cls, t["url"], t.get("param")))
            ran.append(cls)
            ran_this_round += 1
        if ran_this_round == 0:
            break

    return (f"Orchestrated assessment over {len(inventory)} surface items: ran "
            f"{len(ran)} specialist(s) [{', '.join(ran) or 'none'}].")
