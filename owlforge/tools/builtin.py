"""Phase 1 tools. Enough to prove the loop does something real against a target.

NOTE: http_request uses the sandbox agentd (captured by mitmproxy) when a sandbox is
up, else a host-side httpx fallback. Structured params/body mean injection payloads
never touch a shell. exec_command remains for non-HTTP tools (nmap, dig, etc.).
"""

from __future__ import annotations

from typing import Any

from owlforge.tools.base import Tool, ToolContext, ToolRegistry


async def _think(args: dict[str, Any], ctx: ToolContext) -> str:
    thought = str(args.get("thought", "")).strip()
    ctx.emit("think", thought[:500])
    return "Noted. Proceed with a concrete action."


async def _note(args: dict[str, Any], ctx: ToolContext) -> str:
    title = str(args.get("title", "note"))
    ctx.emit("note", f"{title}: {str(args.get('content',''))[:300]}")
    return f"Note saved: {title}"


def _normalize_params(params):
    """Models sometimes pre-URL-encode payloads in params (e.g. "%27"); httpx would
    then encode the '%' again (-> "%2527"), corrupting the payload and causing false
    negatives. If a value already looks percent-encoded, decode it once so it hits the
    wire correctly whether the model passed a raw quote or a pre-encoded one."""
    import re
    from urllib.parse import unquote

    if not isinstance(params, dict):
        return params
    out = {}
    for k, v in params.items():
        if isinstance(v, str) and re.search(r"%[0-9A-Fa-f]{2}", v):
            out[k] = unquote(v)
        else:
            out[k] = v
    return out


async def _http_request(args: dict[str, Any], ctx: ToolContext) -> str:
    method = str(args.get("method", "GET")).upper()
    url = str(args.get("url", "")).strip()
    if not url:
        return "error: 'url' is required"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    headers = {**(ctx.session_headers or {}), **(args.get("headers") or {})} or None
    params = _normalize_params(args.get("params") or None)
    body = args.get("body")
    ctx.emit("tool_call", f"http_request {method} {url}")
    if ctx.sandbox is not None:
        import asyncio

        try:
            d = await asyncio.to_thread(
                ctx.sandbox.http_request, method, url, headers=headers, params=params, body=body
            )
        except Exception as e:
            return f"error: {type(e).__name__}: {e}"
    else:
        import httpx

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as c:
                r = await c.request(method, url, headers=headers, params=params, content=body)
            d = {"status": r.status_code, "final_url": str(r.url),
                 "headers": dict(r.headers), "body": r.text}
        except Exception as e:
            return f"error: {type(e).__name__}: {e}"
    if "error" in d:
        return f"error: {d['error']}"
    try:
        from owlforge.engine.ledger import record_attempt
        record_attempt(ctx.assessment_id, url, method, args.get("params") or None, d.get("status"))
    except Exception:
        pass
    hdrs = {k: v for k, v in list(d.get("headers", {}).items())[:15]}
    return (f"status={d.get('status')}\nfinal_url={d.get('final_url')}\n"
            f"headers={hdrs}\nbody[:3000]:\n{str(d.get('body', ''))[:3000]}")


async def _exec_command(args: dict[str, Any], ctx: ToolContext) -> str:
    if ctx.sandbox is None:
        return "error: no sandbox available. exec_command requires the owlforge-sandbox container."
    command = str(args.get("command", "")).strip()
    if not command:
        return "error: 'command' is required"
    workdir = args.get("workdir")
    timeout_ms = int(args.get("timeout_ms", 60_000))
    ctx.emit("tool_call", f"exec_command: {command[:120]}")
    try:
        import asyncio

        r = await asyncio.to_thread(ctx.sandbox.exec, command, workdir=workdir, timeout_ms=timeout_ms)
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"
    head = f"exit={r.exit_code} ({r.duration_ms}ms{' TIMEOUT' if r.timed_out else ''})"
    body = f"STDOUT:\n{r.stdout[:6000]}\nSTDERR:\n{r.stderr[:2000]}"
    return f"{head}\n{body}"


async def _list_requests(args: dict[str, Any], ctx: ToolContext) -> str:
    if ctx.sandbox is None:
        return "error: no sandbox available."
    import asyncio

    limit = int(args.get("limit", 50))
    flows = await asyncio.to_thread(ctx.sandbox.proxy_flows, limit)
    if not flows:
        return ("No captured requests yet. Traffic from exec_command tools (curl/httpx/"
                "nuclei) is proxied and captured — run some first, then list again.")
    lines = [
        f"{f.get('status')} {f.get('method')} {f.get('url')} "
        f"[{f.get('content_type', '')}, {f.get('resp_len', 0)}b]"
        for f in flows
    ]
    return "\n".join(lines)


async def _create_finding(args: dict[str, Any], ctx: ToolContext) -> str:
    import secrets

    from owlforge.store.db import session
    from owlforge.store.models import Finding

    title = str(args.get("title", "")).strip()
    if not title:
        return "error: 'title' is required"
    fid = f"find_{secrets.token_hex(5)}"
    severity = str(args.get("severity", "medium"))
    finding = Finding(
        id=fid,
        assessment_id=ctx.assessment_id,
        title=title,
        severity=severity,
        confidence=str(args.get("confidence", "medium")),
        target=str(args.get("target", ctx.target)),
        endpoint=str(args.get("endpoint", "")) or None,
        method=str(args.get("method", "")) or None,
        technical_analysis=str(args.get("technical_analysis", "")),
        proof_of_concept=str(args.get("proof_of_concept", "")),
        impact=str(args.get("impact", "")),
        remediation=str(args.get("remediation", "")),
        repro_command=str(args.get("repro_command", "")),
        repro_method=str(args.get("repro_method", "GET") or "GET"),
        repro_url=str(args.get("repro_url", "")),
        repro_params=dict(args.get("repro_params", {}) or {}),
        repro_body=str(args.get("repro_body", "")),
        success_signal=str(args.get("success_signal", "")),
        evidence=list(args.get("evidence", []) or []),
        status="candidate",
        filed_by_agent_id=ctx.agent_id if hasattr(ctx, "agent_id") else None,
    )
    try:
        with session() as s:
            s.add(finding)
            s.commit()
    except Exception as e:
        return f"error saving finding: {type(e).__name__}: {e}"
    ctx.emit("finding", f"candidate filed: [{severity}] {title}")
    return (f"Finding {fid} filed as candidate. It will be VALIDATED by re-running your "
            f"repro_command and checking for success_signal — supply both for auto-validation.")


async def _finish(args: dict[str, Any], ctx: ToolContext) -> str:
    summary = str(args.get("summary", "")).strip()
    ctx.emit("finish", summary[:1000])
    return "Assessment loop complete."


def build_registry(with_sandbox: bool = False) -> ToolRegistry:
    reg = ToolRegistry()
    reg.add(Tool(
        name="think",
        description="Plan your next step before acting. Does not touch the target.",
        parameters={"type": "object", "properties": {"thought": {"type": "string"}}, "required": ["thought"]},
        run=_think,
    ))
    reg.add(Tool(
        name="http_request",
        description=("Make an HTTP request; returns status, headers, and a body snippet. Put "
                     "injection payloads in `params` or `body` — they are encoded safely (no "
                     "shell). Routed through the sandbox + capturing proxy when available."),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "description": "GET|POST|PUT|... (default GET)"},
                "params": {"type": "object", "description": "query params; values auto-encoded"},
                "headers": {"type": "object"},
                "body": {"type": "string", "description": "raw request body"},
            },
            "required": ["url"],
        },
        run=_http_request,
    ))
    reg.add(Tool(
        name="note",
        description="Record an observation or piece of evidence for later.",
        parameters={
            "type": "object",
            "properties": {"title": {"type": "string"}, "content": {"type": "string"}},
            "required": ["title", "content"],
        },
        run=_note,
    ))
    reg.add(Tool(
        name="create_finding",
        description=("File a vulnerability finding as a CANDIDATE. For auto-validation, PREFER a "
                     "structured repro: repro_url + repro_params (RAW payload values) + success_signal "
                     "(text present ONLY when vulnerable). owlforge re-issues it via http_request (no "
                     "shell) and confirms the signal. repro_command is a legacy fallback."),
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "description": "critical|high|medium|low|info"},
                "confidence": {"type": "string", "description": "low|medium|high"},
                "endpoint": {"type": "string"},
                "method": {"type": "string"},
                "technical_analysis": {"type": "string"},
                "proof_of_concept": {"type": "string"},
                "impact": {"type": "string"},
                "remediation": {"type": "string"},
                "repro_url": {"type": "string", "description": "PREFERRED: full URL to re-issue (no shell)"},
                "repro_method": {"type": "string", "description": "HTTP method for repro_url (default GET)"},
                "repro_params": {"type": "object", "description": "PREFERRED: repro params, RAW payload values"},
                "repro_body": {"type": "string", "description": "raw body for the repro request"},
                "repro_command": {"type": "string", "description": "fallback shell command (avoid quote payloads)"},
                "success_signal": {"type": "string", "description": "text present ONLY when vulnerable"},
            },
            "required": ["title", "severity"],
        },
        run=_create_finding,
    ))
    reg.add(Tool(
        name="finish",
        description="End the assessment. Provide a concise summary of what you found.",
        parameters={"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]},
        run=_finish,
        lifecycle=True,
    ))
    if with_sandbox:
        reg.add(Tool(
            name="exec_command",
            description=("Run a shell command inside the isolated sandbox container "
                         "(curl, nmap, dig, jq, etc.). Returns exit code, stdout, stderr."),
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "workdir": {"type": "string", "description": "default /workspace"},
                    "timeout_ms": {"type": "number", "description": "default 60000"},
                },
                "required": ["command"],
            },
            run=_exec_command,
        ))
        reg.add(Tool(
            name="list_requests",
            description=("List HTTP requests/responses captured by the sandbox proxy "
                         "(method, URL, status, type, size). Use after running tools."),
            parameters={"type": "object", "properties": {"limit": {"type": "number"}}},
            run=_list_requests,
        ))
    return reg
