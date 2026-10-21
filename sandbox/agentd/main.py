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


def _pkill(name: str) -> None:
    try:
        subprocess.run(["pkill", "-f", name], stdout=_DEVNULL, stderr=_DEVNULL)
    except Exception:
        pass


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
    procs: list = []
    try:
        # tear down any previous X stack, then bring up Xvfb -> x11vnc -> websockify(noVNC)
        for name in ("websockify", "x11vnc", "Xvfb"):
            _pkill(name)
        await asyncio.sleep(0.3)
        procs.append(subprocess.Popen(["Xvfb", display, "-screen", "0", "1360x900x24"],
                                      stdout=_DEVNULL, stderr=_DEVNULL))
        await asyncio.sleep(1.0)
        subprocess.Popen(["x11vnc", "-display", display, "-nopw", "-forever", "-shared",
                          "-rfbport", "5900", "-quiet"], env=env, stdout=_DEVNULL, stderr=_DEVNULL)
        procs.append(subprocess.Popen(["websockify", "--web=/usr/share/novnc",
                                       str(_NOVNC_PORT), "localhost:5900"],
                                      stdout=_DEVNULL, stderr=_DEVNULL))
        await asyncio.sleep(1.0)
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
            try:
                pr.terminate()
            except Exception:
                pass
        return {"error": f"sso start failed: {type(e).__name__}: {e}"}

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
        _pkill(name)
    return {"storage_state": state}



class InteractRequest(BaseModel):
    url: str
    token: str
    headers: dict[str, str] | None = None
    check_url: str | None = None
    wait_until: str = "load"
    timeout_ms: int = 20_000


@app.post("/interact", dependencies=[Depends(auth)])
async def interact(req: InteractRequest) -> dict:
    """Browser-driven form interaction for formless/SPA UIs and STORED XSS. Fills every
    text input/textarea/contenteditable with a sentinel payload, clicks a submit-like
    control, then checks execution — on a given check_url (stored) or the same page."""
    import asyncio

    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"error": f"playwright unavailable: {e}"}
    dialogs: list[str] = []
    payload = '"><img src=x onerror="window.__owl_xss=' + "'" + req.token + "'" + '">'
    filled = 0
    marker = None
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(extra_http_headers=req.headers or {},
                                                ignore_https_errors=True)
            page = await context.new_page()
            page.on("dialog", lambda d: (dialogs.append(d.message or ""),
                                         asyncio.ensure_future(d.dismiss())))
            await page.goto(req.url, wait_until=req.wait_until, timeout=req.timeout_ms)
            sel = ("input[type=text], input[type=search], input[type=url], input[type=email], "
                   "input:not([type]), textarea, [contenteditable='true']")
            for el in await page.query_selector_all(sel):
                try:
                    await el.fill(payload)
                    filled += 1
                except Exception:
                    try:
                        await el.evaluate("(e,v)=>{e.value=v; if('textContent' in e) e.textContent=v;}", payload)
                        filled += 1
                    except Exception:
                        pass
            btn = (await page.query_selector("button[type=submit]")
                   or await page.query_selector("input[type=submit]")
                   or await page.query_selector("button"))
            if btn:
                try:
                    await btn.click(timeout=4000)
                except Exception:
                    pass
            await page.wait_for_timeout(900)
            if req.check_url:
                await page.goto(req.check_url, wait_until=req.wait_until, timeout=req.timeout_ms)
                await page.wait_for_timeout(600)
            try:
                marker = await page.evaluate("() => window.__owl_xss || null")
            except Exception:
                marker = None
            await browser.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "filled": filled}
    via = ""
    executed = False
    if marker is not None and str(marker) == req.token:
        executed, via = True, "script-exec (window.__owl_xss)"
    elif any(req.token in d for d in dialogs):
        executed, via = True, "dialog"
    return {"submitted": filled > 0, "filled": filled, "executed": executed, "via": via}



class MapRequest(BaseModel):
    url: str
    headers: dict[str, str] | None = None
    max_pages: int = 12
    max_clicks: int = 10
    wait_until: str = "networkidle"
    timeout_ms: int = 20_000


@app.post("/map", dependencies=[Depends(auth)])
async def map_app(req: MapRequest) -> dict:
    """Browser-driven INTERACTIVE recon for SPAs. Drives real Chromium like a user:
    loads the app, follows same-origin in-app navigation (bounded BFS), and clicks
    disclosure/nav controls (tabs, menus, accordions) to reveal lazy-loaded surface.
    Captures EVERY network request the app makes (XHR/fetch/document/websocket) via a
    context-level listener -- this is how formless/JS-built API calls that never appear
    in the raw HTML are discovered. It is strictly NON-DESTRUCTIVE: it never fills or
    submits forms and never clicks submit controls (mutations are out of scope here).
    Returns a structured map: pages, requests, forms, links, websockets."""
    from urllib.parse import urlparse, urlsplit, urlunsplit

    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"error": f"playwright unavailable: {e}"}

    def _norm(u: str) -> str:
        try:
            p = urlsplit(u)
            return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
        except Exception:
            return u

    origin_host = urlparse(req.url).netloc
    reqs: dict[tuple, dict] = {}
    wsockets: set[str] = set()

    def _same_site(netloc: str) -> bool:
        if not netloc:
            return True  # relative -> same
        a = origin_host.split(":")[0].split(".")
        b = netloc.split(":")[0].split(".")
        return a[-2:] == b[-2:]

    def _on_request(r) -> None:
        try:
            u = r.url
            nl = urlparse(u).netloc
            if not _same_site(nl):
                return
            if u.lower().split("?")[0].endswith(
                (".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
                 ".ttf", ".ico", ".css", ".map")
            ):
                return
            rt = r.resource_type
            key = (r.method, _norm(u))
            if key not in reqs:
                reqs[key] = {"method": r.method, "url": _norm(u), "type": rt}
        except Exception:
            pass

    def _on_ws(ws) -> None:
        try:
            if _same_site(urlparse(ws.url).netloc):
                wsockets.add(ws.url)
        except Exception:
            pass

    pages: list[dict] = []
    forms: list[dict] = []
    links: set[str] = set()
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(
                extra_http_headers=req.headers or {}, ignore_https_errors=True
            )
            context.on("request", _on_request)
            context.on("websocket", _on_ws)
            page = await context.new_page()

            queue: list[str] = [req.url]
            visited: set[str] = set()
            while queue and len(visited) < req.max_pages:
                url = queue.pop(0)
                if _norm(url) in visited:
                    continue
                visited.add(_norm(url))
                try:
                    await page.goto(url, wait_until=req.wait_until, timeout=req.timeout_ms)
                except Exception:
                    try:
                        await page.goto(url, wait_until="load", timeout=req.timeout_ms)
                    except Exception:
                        continue
                try:
                    await page.wait_for_timeout(700)
                except Exception:
                    pass

                # disclosure/nav clicks: reveal lazy SPA surface WITHOUT submitting anything
                try:
                    toggles = await page.query_selector_all(
                        "[role=tab], [role=menuitem], [aria-haspopup], "
                        "button[aria-expanded], [data-toggle], summary"
                    )
                    clicks = 0
                    for el in toggles:
                        if clicks >= req.max_clicks:
                            break
                        try:
                            in_form = await el.evaluate("e => !!e.closest('form')")
                            etype = (await el.get_attribute("type") or "").lower()
                            if in_form or etype == "submit":
                                continue
                            before = page.url
                            await el.click(timeout=1500, no_wait_after=True)
                            await page.wait_for_timeout(300)
                            if page.url != before:  # navigated away: come back, don't chase
                                await page.goto(url, wait_until="load", timeout=req.timeout_ms)
                                await page.wait_for_timeout(300)
                            clicks += 1
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    title = await page.title()
                except Exception:
                    title = ""
                pages.append({"url": _norm(page.url), "title": (title or "")[:120]})

                # harvest rendered DOM: anchors + forms (with fields)
                try:
                    hrefs = await page.evaluate(
                        "() => Array.from(document.querySelectorAll('a[href]'))"
                        ".map(a => a.href)"
                    )
                except Exception:
                    hrefs = []
                for h in hrefs or []:
                    try:
                        p = urlparse(h)
                        if p.scheme not in ("http", "https") or not _same_site(p.netloc):
                            continue
                        links.add(_norm(h))
                        if _norm(h) not in visited and len(visited) + len(queue) < req.max_pages:
                            queue.append(h)
                    except Exception:
                        pass
                try:
                    page_forms = await page.evaluate(
                        "() => Array.from(document.querySelectorAll('form')).map(f => ({"
                        "action: f.action || location.href,"
                        "method: (f.method || 'GET').toUpperCase(),"
                        "fields: Array.from(f.querySelectorAll('input,textarea,select'))"
                        ".map(i => ({name: i.name || i.id || '', type: i.type || i.tagName.toLowerCase()}))"
                        ".filter(x => x.name)"
                        "}))"
                    )
                except Exception:
                    page_forms = []
                for f in page_forms or []:
                    try:
                        if _same_site(urlparse(f.get("action", "")).netloc):
                            forms.append(f)
                    except Exception:
                        pass
            await browser.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "requests": list(reqs.values())}

    # dedup forms by (action, method, field-name-set)
    seen_f: set[tuple] = set()
    uforms: list[dict] = []
    for f in forms:
        k = (f.get("action"), f.get("method"),
             tuple(sorted(x.get("name", "") for x in f.get("fields", []))))
        if k not in seen_f:
            seen_f.add(k)
            uforms.append(f)
    return {
        "pages": pages[:60],
        "requests": list(reqs.values())[:300],
        "forms": uforms[:60],
        "links": sorted(links)[:200],
        "websockets": sorted(wsockets)[:20],
    }


_OAST: dict[str, object] = {}


def _oast_kill() -> None:
    for p in list(_OAST.values()):
        try:
            p.kill()
        except Exception:
            pass
    _OAST.clear()
    for n in ("interactsh-client", "cloudflared tunnel", "ngrok http", "oast_listener"):
        _pkill(n)


class OastStartRequest(BaseModel):
    provider: str = "interactsh"   # "interactsh" | "tunnel"
    server: str = ""
    token: str = ""
    ngrok_token: str = ""
    port: int = 48080


@app.post("/oast/start", dependencies=[Depends(auth)])
def oast_start(req: OastStartRequest) -> dict:
    """Start a persistent OAST callback provider as a managed subprocess (so it survives
    across requests, unlike /exec). Returns the callback domain + the hits file to poll."""
    import re as _re

    _oast_kill()
    ws = WORKSPACE
    try:
        os.makedirs(ws, exist_ok=True)
    except Exception:
        pass

    if req.provider == "interactsh":
        out_file = os.path.join(ws, "oast.jsonl")
        payload_file = os.path.join(ws, "oast_payload.txt")
        for f in (out_file, payload_file):
            try:
                os.remove(f)
            except Exception:
                pass
        args = ["interactsh-client", "-json", "-o", out_file,
                "-ps", "-psf", payload_file, "-pi", "1", "-duc", "-nf"]
        if req.server:
            args += ["-server", req.server]
        if req.token:
            args += ["-t", req.token]
        log_file = os.path.join(ws, "oast_ish.log")
        try:
            lf = open(log_file, "w")
            p = subprocess.Popen(args, stdout=lf, stderr=lf, stdin=_DEVNULL,
                                 cwd=ws, start_new_session=True)
        except FileNotFoundError:
            return {"error": "interactsh-client not installed in the sandbox image"}
        _OAST["interactsh"] = p
        domain = ""
        for _ in range(20):
            try:
                if os.path.getsize(payload_file) > 0:
                    first = open(payload_file).read().strip().splitlines()
                    if first:
                        domain = first[0].strip()
                        break
            except Exception:
                pass
            time.sleep(1)
        if not domain:
            _oast_kill()
            return {"error": "interactsh did not register (server unreachable / blocked?)"}
        # self-test: public interactsh servers often mismatch the client's crypto and fail to
        # decrypt interactions ("Could not unmarshal interaction data"), which would silently
        # look like "no vulns". Fire a self-callback and confirm it decodes; else report
        # unhealthy so the caller falls through to the tunnel / a configured collaborator.
        try:
            subprocess.run(["bash", "-lc",
                            f"curl -s -m 6 --noproxy '*' http://owlselftest.{domain}/ >/dev/null 2>&1; "
                            f"nslookup owlselftest.{domain} >/dev/null 2>&1 || true"],
                           timeout=12)
        except Exception:
            pass
        # Trust interactsh ONLY if the self-interaction comes back DECODED. On the public
        # servers decryption often fails (garbled -> "could not unmarshal"); absence of a
        # decoded interaction (error, or nothing) means we cannot rely on it -> fall back.
        decoded = False
        for _ in range(16):
            try:
                if "owlselftest" in open(out_file).read():
                    decoded = True
                    break
            except Exception:
                pass
            try:
                low = open(log_file).read().lower()
                if "could not unmarshal" in low or "unmarshal interaction" in low:
                    break
            except Exception:
                pass
            time.sleep(1)
        if not decoded:
            _oast_kill()
            return {"error": "interactsh returned no decodable interaction "
                             "(server/client mismatch or egress blocked) — falling back"}
        return {"mode": "interactsh", "domain": domain, "hits_file": out_file}

    if req.provider == "tunnel":
        port = int(req.port or 48080)
        hits = os.path.join(ws, "oast_hits.log")
        tun = os.path.join(ws, "tun.out")
        listener = os.path.join(ws, "oast_listener.py")
        for f in (hits, tun):
            try:
                os.remove(f)
            except Exception:
                pass
        with open(listener, "w") as fh:
            fh.write(
                "import http.server\n"
                "class H(http.server.BaseHTTPRequestHandler):\n"
                " def _l(self):\n"
                f"  open({hits!r},'a').write(self.path+chr(10))\n"
                "  self.send_response(200); self.end_headers(); self.wfile.write(b'ok')\n"
                " do_GET=_l; do_POST=_l; do_HEAD=_l\n"
                " def log_message(self,*a): pass\n"
                f"http.server.HTTPServer(('127.0.0.1',{port}),H).serve_forever()\n"
            )
        _OAST["listener"] = subprocess.Popen(
            ["python3", listener], stdout=_DEVNULL, stderr=_DEVNULL, stdin=_DEVNULL,
            start_new_session=True)
        if req.ngrok_token:
            targs = ["ngrok", "http", str(port), "--authtoken", req.ngrok_token,
                     "--log", "stdout", "--log-format", "logfmt"]
        else:
            targs = ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"]
        try:
            tf = open(tun, "w")
            _OAST["tunnel"] = subprocess.Popen(targs, stdout=tf, stderr=tf, stdin=_DEVNULL,
                                               start_new_session=True)
        except FileNotFoundError:
            _oast_kill()
            return {"error": "tunnel binary (cloudflared/ngrok) not installed in the image"}
        domain = ""
        for _ in range(24):
            try:
                txt = open(tun).read()
                m = (_re.search(r"https://[a-z0-9.\-]+\.trycloudflare\.com", txt)
                     or _re.search(r"url=https://[a-z0-9.\-]+", txt))
                if m:
                    domain = m.group(0).replace("url=", "").split("://", 1)[1].rstrip("/")
                    break
            except Exception:
                pass
            time.sleep(1)
        if not domain:
            _oast_kill()
            return {"error": "tunnel did not come up (server unreachable / blocked?)"}
        time.sleep(6)  # let the tunnel edge become routable before callbacks are injected
        return {"mode": "tunnel", "domain": domain, "hits_file": hits}

    return {"error": f"unknown provider {req.provider}"}


class OastPollRequest(BaseModel):
    hits_file: str


@app.post("/oast/poll", dependencies=[Depends(auth)])
def oast_poll(req: OastPollRequest) -> dict:
    try:
        return {"data": open(req.hits_file).read()}
    except Exception:
        return {"data": ""}


@app.post("/oast/stop", dependencies=[Depends(auth)])
def oast_stop() -> dict:
    _oast_kill()
    return {"stopped": True}


class ProtoCheckRequest(BaseModel):
    url: str
    probe: str
    headers: dict[str, str] | None = None
    wait_until: str = "load"
    timeout_ms: int = 15_000


@app.post("/proto_check", dependencies=[Depends(auth)])
async def proto_check(req: ProtoCheckRequest) -> dict:
    """Client-side prototype-pollution check. The caller loads a URL carrying a payload like
    ?__proto__[<probe>]=owlPOLLUTED; we render it in real Chromium and report whether the
    page's JS polluted Object.prototype (i.e. Object.prototype[<probe>] === the sentinel).
    Deterministic — only a genuine pollution sink sets the property."""
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"error": f"playwright unavailable: {e}"}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(extra_http_headers=req.headers or {},
                                                ignore_https_errors=True)
            page = await context.new_page()
            try:
                await page.goto(req.url, wait_until=req.wait_until, timeout=req.timeout_ms)
            except Exception as e:
                await browser.close()
                return {"error": f"{type(e).__name__}: {e}", "polluted": False}
            try:
                await page.wait_for_timeout(600)
            except Exception:
                pass
            val = None
            try:
                val = await page.evaluate(
                    "(k) => Object.prototype[k] === undefined ? null : String(Object.prototype[k])",
                    req.probe)
            except Exception:
                val = None
            await browser.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "polluted": False}
    return {"polluted": val == "owlPOLLUTED", "value": val}


class WsProbeRequest(BaseModel):
    url: str
    messages: list[str] | None = None
    headers: dict[str, str] | None = None
    timeout_ms: int = 8000


@app.post("/ws_probe", dependencies=[Depends(auth)])
async def ws_probe(req: WsProbeRequest) -> dict:
    """Connect to a WebSocket, send message(s), and return the responses — so WS
    endpoints can be tested (injection / auth / echo) like any other surface."""
    import asyncio

    try:
        import websockets
    except Exception as e:
        return {"error": f"websockets unavailable: {e}"}
    responses: list[str] = []
    err = ""
    try:
        kw = {"open_timeout": req.timeout_ms / 1000, "close_timeout": 2}
        try:
            ws = await websockets.connect(req.url, additional_headers=req.headers or {}, **kw)
        except TypeError:
            ws = await websockets.connect(req.url, extra_headers=req.headers or {}, **kw)
        try:
            try:
                responses.append(str(await asyncio.wait_for(ws.recv(), timeout=2))[:500])
            except Exception:
                pass
            for m in (req.messages or ["ping"]):
                try:
                    await ws.send(m)
                    responses.append(str(await asyncio.wait_for(ws.recv(), timeout=3))[:500])
                except Exception as e:
                    responses.append(f"__err__:{type(e).__name__}")
        finally:
            await ws.close()
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    return {"connected": err == "", "error": err, "responses": responses[:10]}



class SmuggleRequest(BaseModel):
    url: str
    timeout_s: float = 10.0


@app.post("/smuggle_probe", dependencies=[Depends(auth)])
async def smuggle_probe(req: SmuggleRequest) -> dict:
    """Best-effort, time-based HTTP request-smuggling detection (CL.TE / TE.CL). Sends a
    benign baseline plus ambiguous CL+TE requests over a raw socket and compares read
    timing — a large delay on an ambiguous request suggests a front/back-end desync.
    Detection only (no malicious smuggled request); confirm manually."""
    import socket
    import ssl
    import time
    from urllib.parse import urlsplit

    sp = urlsplit(req.url)
    host = sp.hostname or ""
    if not host:
        return {"error": "bad url"}
    tls = sp.scheme == "https"
    port = sp.port or (443 if tls else 80)

    def _send(raw: str) -> float:
        try:
            sock = socket.create_connection((host, port), timeout=8)
            if tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        except Exception:
            return -1.0
        try:
            sock.sendall(raw.encode())
            sock.settimeout(req.timeout_s)
            start = time.time()
            try:
                while True:
                    if not sock.recv(4096):
                        break
            except Exception:
                pass
            return time.time() - start
        finally:
            try:
                sock.close()
            except Exception:
                pass

    base = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    clte = (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX\r\n")
    tecl = (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nX\r\n")
    t_base = _send(base)
    t_clte = _send(clte)
    t_tecl = _send(tecl)
    if t_base < 0:
        return {"error": "connect failed", "baseline": t_base}
    # a probe that hangs far longer than baseline (near the read timeout) = potential desync
    thresh = max(t_base * 3 + 1.0, 4.0)
    potential = (t_clte >= thresh and t_clte >= req.timeout_s * 0.8) or \
                (t_tecl >= thresh and t_tecl >= req.timeout_s * 0.8)
    kind = "CL.TE" if t_clte >= thresh else ("TE.CL" if t_tecl >= thresh else "")
    return {"potential": potential, "kind": kind,
            "baseline_s": round(t_base, 2), "clte_s": round(t_clte, 2), "tecl_s": round(t_tecl, 2)}
