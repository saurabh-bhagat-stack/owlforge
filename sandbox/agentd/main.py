"""owlforge-agentd — the in-container control daemon.

The engine treats the sandbox as a service with a typed contract, not a shell.
Phase 2 exposes:
  GET  /health            readiness (no auth) — engine gates the mission on this
  POST /exec              run a command, return exit/stdout/stderr/timing (auth)
  GET  /file?path=...     read a file from the workspace for evidence (auth)

Auth: if OWLFORGE_AGENTD_TOKEN is set in the environment, every non-health request
must carry `Authorization: Bearer <token>`. The engine generates a per-container
token and injects it, so the published localhost port can't be driven by anything
else on the host. Streaming output and long-running processes come in a later pass.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

app = FastAPI(title="owlforge-agentd", version="0.2.0")

TOKEN = os.environ.get("OWLFORGE_AGENTD_TOKEN", "")
WORKSPACE = os.environ.get("OWLFORGE_WORKSPACE", "/workspace")
MAX_OUTPUT = 200_000  # chars per stream, hard cap


def auth(authorization: str = Header(default="")) -> None:
    if not TOKEN:
        return  # dev / no-auth mode
    expected = f"Bearer {TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="bad or missing bearer token")


class ExecRequest(BaseModel):
    command: str
    workdir: str | None = None
    timeout_ms: int = 60_000
    bypass_proxy: bool = False


class ExecResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "owlforge-agentd", "version": app.version}


@app.post("/exec", response_model=ExecResult, dependencies=[Depends(auth)])
async def exec_command(req: ExecRequest) -> ExecResult:
    workdir = req.workdir or WORKSPACE
    # pipefail so failures inside pipelines surface; optional proxy unset.
    prefix = (
        "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY; "
        if req.bypass_proxy
        else ""
    )
    wrapped = f"set -o pipefail; {prefix}{req.command}"

    start = time.monotonic()
    try:
        os.makedirs(workdir, exist_ok=True)
    except Exception:
        pass
    proc = await asyncio.create_subprocess_exec(
        "bash", "-lc", wrapped,
        cwd=workdir if os.path.isdir(workdir) else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    timed_out = False
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=max(1, req.timeout_ms) / 1000)
        code = proc.returncode or 0
    except TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except Exception:
            pass
        out, err = b"", b"(killed: timeout)"
        code = 124
    dur = int((time.monotonic() - start) * 1000)

    so = out.decode("utf-8", "replace")
    se = err.decode("utf-8", "replace")
    truncated = len(so) > MAX_OUTPUT or len(se) > MAX_OUTPUT
    return ExecResult(
        exit_code=code, stdout=so[:MAX_OUTPUT], stderr=se[:MAX_OUTPUT],
        duration_ms=dur, timed_out=timed_out, truncated=truncated,
    )


@app.get("/file", dependencies=[Depends(auth)])
def read_file(path: str = Query(...)) -> dict:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = fh.read(MAX_OUTPUT)
        return {"path": path, "content": data}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="not found") from None
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@app.get("/proxy/flows", dependencies=[Depends(auth)])
def proxy_flows(limit: int = Query(100)) -> dict:
    """Return the most recent captured HTTP flows (from the mitmproxy addon)."""
    path = os.environ.get("OWLFORGE_FLOWLOG", os.path.join(WORKSPACE, ".owlforge/flows.jsonl"))
    flows: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()[-max(1, limit):]
        for ln in lines:
            try:
                flows.append(json.loads(ln))
            except Exception:
                pass
    except FileNotFoundError:
        pass
    return {"flows": flows, "count": len(flows)}


class HttpRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] | None = None
    params: dict[str, str] | None = None
    body: str | None = None
    follow_redirects: bool = True
    timeout_ms: int = 30_000


@app.post("/http", dependencies=[Depends(auth)])
def http_request(req: HttpRequest) -> dict:
    """Issue an HTTP request from inside the sandbox (through mitmproxy, captured).

    Structured params mean no shell quoting — injection payloads go in `params`/`body`
    safely. Uses the system CA bundle so mitmproxy's intercepting cert is trusted."""
    import httpx

    ca = "/etc/ssl/certs/ca-certificates.crt"
    verify = ca if os.path.exists(ca) else True
    try:
        with httpx.Client(verify=verify, trust_env=True,
                          follow_redirects=req.follow_redirects,
                          timeout=max(1, req.timeout_ms) / 1000) as c:
            r = c.request(req.method.upper(), req.url, headers=req.headers,
                          params=req.params, content=req.body)
        return {
            "status": r.status_code,
            "final_url": str(r.url),
            "headers": dict(r.headers),
            "body": r.text[:MAX_OUTPUT],
            "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


class RenderRequest(BaseModel):
    url: str
    headers: dict[str, str] | None = None
    wait_until: str = "networkidle"
    timeout_ms: int = 30_000


@app.post("/render", dependencies=[Depends(auth)])
async def render(req: RenderRequest) -> dict:
    """Headless-Chromium render: load the URL (run its JS), return the rendered DOM so
    the engine can extract surface that is not in the raw HTML (SPA/JS-built links).
    Carries auth via extra_http_headers so it works authenticated too."""
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"error": f"playwright unavailable: {e}"}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(
                extra_http_headers=req.headers or {}, ignore_https_errors=True
            )
            page = await context.new_page()
            resp = await page.goto(req.url, wait_until=req.wait_until, timeout=req.timeout_ms)
            try:
                await page.wait_for_timeout(800)  # settle late JS
            except Exception:
                pass
            html = await page.content()
            status = resp.status if resp else 0
            final_url = page.url
            await browser.close()
            return {"status": status, "final_url": final_url, "html": html[:MAX_OUTPUT]}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


class XssCheckRequest(BaseModel):
    url: str
    token: str
    headers: dict[str, str] | None = None
    wait_until: str = "load"
    timeout_ms: int = 15_000


@app.post("/xss_check", dependencies=[Depends(auth)])
async def xss_check(req: XssCheckRequest) -> dict:
    """Confirm XSS by EXECUTION, not reflection. The caller injects a sentinel
    payload that (if it runs) sets `window.__owl_xss = token` and/or fires a
    dialog containing the token. We render the URL in real Chromium and report
    whether the token actually executed — so HTML-encoded/escaped reflections and
    non-executing sinks are NOT confirmed, while DOM/stored XSS is."""
    import asyncio

    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"error": f"playwright unavailable: {e}"}
    dialogs: list[str] = []
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(
                extra_http_headers=req.headers or {}, ignore_https_errors=True
            )
            page = await context.new_page()

            def _on_dialog(d) -> None:
                dialogs.append(d.message or "")
                asyncio.ensure_future(d.dismiss())

            page.on("dialog", _on_dialog)
            try:
                resp = await page.goto(req.url, wait_until=req.wait_until, timeout=req.timeout_ms)
            except Exception as e:
                resp = None
                dialogs.append(f"__nav_error__:{type(e).__name__}")
            try:
                await page.wait_for_timeout(500)  # let onerror/async sinks fire
            except Exception:
                pass
            marker = None
            try:
                marker = await page.evaluate("() => window.__owl_xss || null")
            except Exception:
                marker = None
            status = resp.status if resp else 0
            await browser.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

    executed = False
    via = ""
    if marker is not None and str(marker) == req.token:
        executed, via = True, "script-exec (window.__owl_xss)"
    elif any(req.token in d for d in dialogs):
        executed, via = True, "dialog (alert/confirm/prompt)"
    return {"executed": executed, "via": via, "status": status, "dialogs": dialogs[:5]}



# --- interactive SSO/MFA capture: headed Chromium in-container, exposed via noVNC ---
_SSO: dict[str, dict] = {}
_NOVNC_PORT = int(os.environ.get("OWLFORGE_NOVNC_PORT", "6080"))
_DEVNULL = subprocess.DEVNULL


class SsoStartRequest(BaseModel):
    url: str
    headers: dict[str, str] | None = None


class SsoFinishRequest(BaseModel):
    session_id: str


@app.post("/sso/start", dependencies=[Depends(auth)])
async def sso_start(req: SsoStartRequest) -> dict:
    """Launch a HEADED Chromium at the login URL on a virtual display and expose it via
    noVNC so the operator can complete SSO/MFA. Returns a session id; the browser stays
    alive until /sso/finish captures its storage_state."""
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"error": f"playwright unavailable: {e}"}

    display = ":99"
    env = dict(os.environ)
    env["DISPLAY"] = display
    # tear down any previous X stack, then bring up Xvfb -> x11vnc -> websockify(noVNC)
    for name in ("websockify", "x11vnc", "Xvfb"):
        subprocess.run(["pkill", "-f", name], stdout=_DEVNULL, stderr=_DEVNULL)
    await asyncio.sleep(0.3)
    procs = []
    procs.append(subprocess.Popen(["Xvfb", display, "-screen", "0", "1360x900x24"],
                                  stdout=_DEVNULL, stderr=_DEVNULL))
    await asyncio.sleep(1.0)
    subprocess.Popen(["x11vnc", "-display", display, "-nopw", "-forever", "-shared",
                      "-rfbport", "5900", "-quiet"], env=env, stdout=_DEVNULL, stderr=_DEVNULL)
    procs.append(subprocess.Popen(["websockify", "--web=/usr/share/novnc",
                                   str(_NOVNC_PORT), "localhost:5900"],
                                  stdout=_DEVNULL, stderr=_DEVNULL))
    await asyncio.sleep(1.0)

    try:
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(
            headless=False, env=env,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--start-maximized"])
        context = await browser.new_context(extra_http_headers=req.headers or {},
                                            ignore_https_errors=True, no_viewport=True)
        page = await context.new_page()
        try:
            await page.goto(req.url, wait_until="load", timeout=30_000)
        except Exception:
            pass
    except Exception as e:
        for pr in procs:
            pr.terminate()
        return {"error": f"browser launch failed: {type(e).__name__}: {e}"}

    sid = secrets.token_hex(6)
    _SSO[sid] = {"pw": pw, "browser": browser, "context": context, "procs": procs}
    return {"session_id": sid, "novnc_port": _NOVNC_PORT,
            "novnc_path": "/vnc.html?autoconnect=1&resize=scale"}


@app.post("/sso/finish", dependencies=[Depends(auth)])
async def sso_finish(req: SsoFinishRequest) -> dict:
    """Capture the authenticated storage_state (cookies + localStorage) from the live
    SSO session, tear down the browser + X stack, and return it for reuse."""
    sess = _SSO.pop(req.session_id, None)
    if not sess:
        return {"error": "no such sso session"}
    state = {}
    try:
        state = await sess["context"].storage_state()
    except Exception as e:
        state = {"error": f"storage_state failed: {type(e).__name__}: {e}"}
    for key in ("browser", "pw"):
        try:
            obj = sess.get(key)
            await (obj.close() if key == "browser" else obj.stop())
        except Exception:
            pass
    for pr in sess.get("procs", []):
        try:
            pr.terminate()
        except Exception:
            pass
    for name in ("websockify", "x11vnc", "Xvfb"):
        subprocess.run(["pkill", "-f", name], stdout=_DEVNULL, stderr=_DEVNULL)
    return {"storage_state": state}
