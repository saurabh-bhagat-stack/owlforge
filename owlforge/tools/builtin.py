"""Phase 1 tools. Enough to prove the loop does something real against a target.

NOTE: http_fetch runs ENGINE-SIDE (host) for now. In Phase 2 all target-touching
execution moves into the sandbox over the agentd RPC; this host-side fetch is a
temporary stand-in so Phase 1 can demonstrate observe->act with a live model.
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


async def _http_fetch(args: dict[str, Any], ctx: ToolContext) -> str:
    import httpx

    url = str(args.get("url", "")).strip()
    method = str(args.get("method", "GET")).upper()
    if not url:
        return "error: 'url' is required"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    ctx.emit("tool_call", f"http_fetch {method} {url}")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
            r = await client.request(method, url)
            body = r.text[:2000]
            hdrs = {k: v for k, v in list(r.headers.items())[:15]}
            return (
                f"status={r.status_code}\nfinal_url={r.url}\nheaders={hdrs}\n"
                f"body[:2000]:\n{body}"
            )
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"


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
        name="http_fetch",
        description="Fetch a URL and return status, headers, and a body snippet. Use for recon/probing.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Absolute or scheme-less URL"},
                "method": {"type": "string", "description": "HTTP method (default GET)"},
            },
            "required": ["url"],
        },
        run=_http_fetch,
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
