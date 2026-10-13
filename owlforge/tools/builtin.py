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


async def _finish(args: dict[str, Any], ctx: ToolContext) -> str:
    summary = str(args.get("summary", "")).strip()
    ctx.emit("finish", summary[:1000])
    return "Assessment loop complete."


def build_registry() -> ToolRegistry:
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
    return reg
