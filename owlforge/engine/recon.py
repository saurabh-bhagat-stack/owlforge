"""Deterministic recon: crawl the target and build an explicit attack-surface
inventory (endpoints + their parameters + forms).

This is intentionally NOT LLM-driven — benchmarks showed models under-enumerate. A
reliable crawler maps the surface; the testing agent then works through it item by
item. Honors the session (authenticated recon) via the injected request_fn.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import parse_qs, urljoin, urlparse

RequestFn = Callable[..., dict]


def _origin(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def _strip(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}{p.path}"


def extract_surface(base_url: str, html: str) -> list[dict]:
    """Pure HTML->surface extraction (links + forms + query params). Testable offline."""
    out: list[dict] = []
    origin = _origin(base_url)

    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html or "", re.I):
        href = m.group(1).strip()
        if not href or href.lower().startswith(("mailto:", "javascript:", "tel:", "data:")):
            continue
        url = urljoin(base_url, href)
        if _origin(url) != origin:
            continue
        params = sorted(parse_qs(urlparse(url).query).keys())
        out.append({"url": _strip(url), "method": "GET", "params": params, "source": "link"})

    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        am = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        action = urljoin(base_url, am.group(1)) if am and am.group(1) else base_url
        if _origin(action) != origin:
            continue
        mm = re.search(r'method=["\']?([A-Za-z]+)', attrs, re.I)
        method = (mm.group(1).upper() if mm else "GET")
        names = sorted(set(re.findall(r'name=["\']([^"\']+)["\']', inner, re.I)))
        out.append({"url": _strip(action), "method": method, "params": names, "source": "form"})

    # 3) ANY /path?query occurrence in the raw HTML (catches param links not in <a href>
    #    — JS-built nav, data-attributes, inline JSON). This recovers e.g. ?category=.
    for m in re.finditer(r"(/[A-Za-z0-9_\-./]+)\?([A-Za-z0-9_\-=&%]+)", html or ""):
        path, qs = m.group(1), m.group(2)
        url = urljoin(base_url, path)
        if _origin(url) != origin:
            continue
        keys = sorted({k for k in re.findall(r"([A-Za-z_][A-Za-z0-9_]{0,30})=", qs)})
        if keys:
            out.append({"url": _strip(url), "method": "GET", "params": keys, "source": "html"})

    return out


def _dedup(items: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for it in items:
        key = (it["method"], it["url"], tuple(sorted(it["params"])))
        seen[key] = it
    return list(seen.values())


def crawl(
    target: str,
    request_fn: RequestFn,
    max_pages: int = 20,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    visited: set[str] = set()
    queue: list[str] = [target]
    inventory: list[dict] = []
    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        r = request_fn("GET", url) or {}
        html = r.get("body", "") or ""
        items = extract_surface(url, html)
        inventory.extend(items)
        for it in items:
            if it["source"] == "link" and it["url"] not in visited and len(visited) + len(queue) < max_pages:
                queue.append(it["url"])
    inv = _dedup(inventory)
    log(f"recon: crawled {len(visited)} page(s), {len(inv)} surface item(s)")
    return inv


def persist(assessment_id: str, inventory: list[dict]) -> None:
    from owlforge.store.db import session
    from owlforge.store.models import SurfaceItem
    with session() as s:
        for it in inventory:
            s.add(SurfaceItem(id=f"surf_{secrets.token_hex(5)}", assessment_id=assessment_id,
                              url=it["url"], method=it["method"], params=it.get("params", []),
                              source=it.get("source", "link")))
        s.commit()


def render_inventory(inventory: list[dict], limit: int = 40) -> str:
    """Compact inventory text for the testing agent's prompt — params emphasized."""
    withp = [it for it in inventory if it.get("params")]
    without = [it for it in inventory if not it.get("params")]
    lines = []
    for it in (withp + without)[:limit]:
        p = ", ".join(it["params"]) if it.get("params") else "(no params)"
        lines.append(f"- {it['method']} {it['url']}  params: {p}  [{it['source']}]")
    extra = len(inventory) - min(len(inventory), limit)
    if extra > 0:
        lines.append(f"- … and {extra} more")
    return "\n".join(lines) if lines else "(no surface discovered)"


_SCRIPT_SRC = None  # compiled lazily


def extract_script_srcs(base_url: str, html: str) -> list[str]:
    import re
    origin = _origin(base_url)
    out = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html or "", re.I):
        u = urljoin(base_url, m.group(1))
        if _origin(u) == origin and u not in out:
            out.append(u)
    return out


def extract_js_endpoints(origin: str, js: str) -> tuple[list[dict], set[str]]:
    """From a JS bundle: precise path?query literals (endpoint+params), bare path
    literals (endpoints), and loose param names seen. Regex-based (noisy by nature)."""
    import re
    items: dict[tuple, set] = {}
    # 1) path?query literals -> precise endpoint + params
    for m in re.finditer(r'["\'](/[A-Za-z0-9_\-./]+)\?([A-Za-z0-9_\-=&%${}.]+)["\']', js or ""):
        path, qs = m.group(1), m.group(2)
        keys = sorted({k for k in re.findall(r'([A-Za-z_][A-Za-z0-9_]{0,30})=', qs)})
        items.setdefault((origin + path, "GET"), set()).update(keys)
    # 2) bare path literals -> endpoints (skip asset/static)
    _skip = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".map",
             ".ico", ".gif", ".webp", ".ttf")
    for m in re.finditer(r'["\'](/[A-Za-z0-9_][A-Za-z0-9_\-./]{1,70})["\']', js or ""):
        path = m.group(1)
        if path.lower().endswith(_skip) or "//" in path:
            continue
        items.setdefault((origin + path, "GET"), set())
    # 3) loose param names anywhere (?x= or &x=)
    loose = {m.group(1) for m in re.finditer(r'[?&]([A-Za-z_][A-Za-z0-9_]{0,30})=', js or "")}
    out = [{"url": url, "method": method, "params": sorted(ps), "source": "js"} for (url, method), ps in items.items()]
    return out, loose


def js_recon(
    target: str,
    request_fn: RequestFn,
    max_js: int = 12,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    origin = _origin(target)
    r = request_fn("GET", target) or {}
    srcs = extract_script_srcs(target, r.get("body", "") or "")
    endpoints: list[dict] = []
    loose_params: set[str] = set()
    for src in srcs[:max_js]:
        jr = request_fn("GET", src) or {}
        eps, loose = extract_js_endpoints(origin, jr.get("body", "") or "")
        endpoints.extend(eps)
        loose_params |= loose
    # attach loose param names to the base app endpoints that have none, best-effort:
    if loose_params:
        for ep in endpoints:
            if not ep["params"]:
                # only attach to short app paths (not deep api paths) to limit noise
                if ep["url"].count("/") <= 4:
                    ep["params"] = sorted(loose_params)[:12]
    log(f"js recon: {len(srcs)} script(s), {len(endpoints)} js endpoint(s), {len(loose_params)} param name(s)")
    return endpoints


def recon_phase(
    assessment_id: str,
    target: str,
    session_headers: dict | None,
    sandbox_client,
    max_pages: int = 25,
    network_recon_enabled: bool = False,
    browser_recon_enabled: bool = False,
    log: Callable[[str], None] = lambda m: None,
) -> str:
    """Run deterministic recon, persist the inventory, return it rendered for the prompt."""

    def request_fn(method, url, headers=None, params=None, body=None):
        hdrs = {**(session_headers or {}), **(headers or {})} or None
        if sandbox_client is not None:
            try:
                return sandbox_client.http_request(method, url, headers=hdrs, params=params, body=body)
            except Exception as e:
                return {"error": str(e)}
        import httpx
        try:
            r = httpx.request(method, url, headers=hdrs, params=params, content=body,
                              follow_redirects=True, timeout=20.0)
            return {"status": r.status_code, "headers": dict(r.headers), "body": r.text}
        except Exception as e:
            return {"error": str(e)}

    inv = crawl(target, request_fn, max_pages=max_pages, log=log)
    inv += content_discovery(target, sandbox_client, session_headers, log=log)
    inv += js_recon(target, request_fn, log=log)
    inv += api_spec_discovery(target, request_fn, log=log)
    inv += graphql_probe(target, request_fn, log=log)
    if browser_recon_enabled:
        _pages = [it["url"] for it in inv if it.get("source") in ("link", "content-discovery")][:6]
        inv += browser_recon(target, sandbox_client, pages=_pages, session_headers=session_headers, log=log)
    inv = _dedup(inv)
    persist(assessment_id, inv)

    fp = fingerprint(target, request_fn)
    header = f"Fingerprint: server={fp.get('server') or '?'}; tech={', '.join(fp.get('tech') or []) or '?'}"
    text = header + "\n\n" + render_inventory(inv)

    if network_recon_enabled:
        net = network_recon(target, sandbox_client, log=log)
        if net.strip():
            text += "\n\n# Network recon (nmap, optional)\n" + net.strip()[:1500]
    return text

WORDLIST = "/opt/owlforge/wordlists/common.txt"
_MATCH_CODES = "200,204,301,302,307,308,401,403,405"


def fingerprint(target: str, request_fn: RequestFn) -> dict:
    """Cheap HTTP fingerprint (mandatory): server + framework hints from the response."""
    r = request_fn("GET", target) or {}
    h = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
    body = (r.get("body") or "").lower()
    sigs = [("React", "react"), ("Next.js", "/_next/"), ("Angular", "ng-app"),
            ("Angular", "angular"), ("Vue", "vue.js"), ("GraphQL", "graphql"),
            ("WordPress", "wp-content"), ("jQuery", "jquery")]
    tech = sorted({name for name, sig in sigs if sig in body})
    return {
        "server": h.get("server", ""),
        "x_powered_by": h.get("x-powered-by", ""),
        "via": h.get("via", ""),
        "tech": tech,
    }


def content_discovery(
    target: str,
    sandbox_client,
    session_headers: dict | None = None,
    wordlist: str = WORDLIST,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    """Brute-force hidden/unlinked paths with ffuf (in-sandbox). Finds what the crawler
    can't — content that isn't linked. Carries the auth session when present."""
    if sandbox_client is None:
        log("content discovery skipped (no sandbox)")
        return []
    base = target.rstrip("/")
    hdr = "".join(f" -H '{k}: {v}'" for k, v in (session_headers or {}).items())
    cmd = (
        f"ffuf -u {base}/FUZZ -w {wordlist} -mc {_MATCH_CODES} -t 40 -s "
        f"-of json -o /workspace/ffuf.json{hdr} >/dev/null 2>&1; cat /workspace/ffuf.json 2>/dev/null"
    )
    try:
        r = sandbox_client.exec(cmd, timeout_ms=180_000)
        import json
        data = json.loads(r.stdout or "{}")
    except Exception as e:
        log(f"content discovery error: {e}")
        return []
    from urllib.parse import urlparse
    out = []
    for res in data.get("results", []) or []:
        u = res.get("url", "")
        if not u:
            continue
        pr = urlparse(u)
        out.append({"url": f"{pr.scheme}://{pr.netloc}{pr.path}", "method": "GET",
                    "params": [], "source": "content-discovery", "status": res.get("status")})
    log(f"content discovery: {len(out)} hidden path(s)")
    return out


def network_recon(target: str, sandbox_client, log: Callable[[str], None] = lambda m: None) -> str:
    """OPTIONAL (scope-gated): port/service discovery via nmap. Off by default."""
    if sandbox_client is None:
        return ""
    from urllib.parse import urlparse
    host = urlparse(target).netloc.split(":")[0]
    try:
        r = sandbox_client.exec(
            f"nmap -Pn -T4 --top-ports 200 -sV {host} 2>&1 | grep -E '^[0-9]+/|Nmap scan' | head -40",
            timeout_ms=240_000,
        )
        log("network recon (nmap) done")
        return r.stdout or ""
    except Exception as e:
        log(f"network recon error: {e}")
        return ""


_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/openapi.yaml", "/api-docs", "/v2/api-docs",
               "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json",
               "/.well-known/openapi.json", "/api/v1/openapi.json"]
_GQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query"]


def api_spec_discovery(target: str, request_fn: RequestFn, log: Callable[[str], None] = lambda m: None) -> list[dict]:
    """Probe for an OpenAPI/Swagger spec and turn its paths into surface items (spec §1.5)."""
    import json
    base = target.rstrip("/")
    origin = _origin(target)
    for sp in _SPEC_PATHS:
        r = request_fn("GET", base + sp) or {}
        if r.get("status") != 200:
            continue
        try:
            spec = json.loads(r.get("body", "") or "")
        except Exception:
            continue
        paths = spec.get("paths") if isinstance(spec, dict) else None
        if not isinstance(paths, dict):
            continue
        out = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                params = []
                if isinstance(op, dict):
                    for pr in op.get("parameters", []) or []:
                        if isinstance(pr, dict) and pr.get("name"):
                            params.append(str(pr["name"]))
                clean = origin + ("/" + path.lstrip("/")).split("{")[0].rstrip("/")
                out.append({"url": clean or origin + "/" + path.lstrip("/"),
                            "method": method.upper(), "params": sorted(set(params)), "source": "api-spec"})
        log(f"api spec {sp}: {len(paths)} path(s) -> {len(out)} operation(s)")
        return out
    return []


def graphql_probe(target: str, request_fn: RequestFn, log: Callable[[str], None] = lambda m: None) -> list[dict]:
    """Detect a GraphQL endpoint + whether introspection is open (spec §2.11)."""
    import json
    base = target.rstrip("/")
    hdr = {"Content-Type": "application/json"}
    for gp in _GQL_PATHS:
        r = request_fn("POST", base + gp, headers=hdr, body=json.dumps({"query": "query{__typename}"})) or {}
        body = (r.get("body", "") or "")
        if r.get("status") in (200, 400) and ("__typename" in body or '"data"' in body or '"errors"' in body):
            intro = request_fn("POST", base + gp, headers=hdr,
                               body=json.dumps({"query": "query{__schema{queryType{name}}}"})) or {}
            on = "__schema" in (intro.get("body", "") or "")
            log(f"graphql endpoint {gp} (introspection {'OPEN' if on else 'closed/unknown'})")
            return [{"url": _strip(base + gp), "method": "POST", "params": ["query"], "source": "graphql"}]
    return []


def browser_recon(
    target: str,
    sandbox_client,
    pages: list[str] | None = None,
    session_headers: dict | None = None,
    max_pages: int = 6,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    """Headless-Chromium render of key pages -> extract surface from the RENDERED DOM.
    Recovers JS-built links/params the raw-HTML crawler can't see (SPAs). Carries the
    auth session, so it works authenticated too. Flag-gated (heavy)."""
    if sandbox_client is None:
        log("browser recon skipped (no sandbox)")
        return []
    urls: list[str] = []
    for u in [target, *(pages or [])]:
        if u not in urls:
            urls.append(u)
    out: list[dict] = []
    rendered = 0
    for u in urls[:max_pages]:
        try:
            d = sandbox_client.render(u, headers=(session_headers or None))
        except Exception as e:
            log(f"render error {u}: {e}")
            continue
        if d.get("error"):
            log(f"render {u}: {d['error']}")
            continue
        out.extend(extract_surface(d.get("final_url", u), d.get("html", "") or ""))
        rendered += 1
    log(f"browser recon: rendered {rendered} page(s), {len(out)} item(s)")
    return out
