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

from owlforge.engine.classify import classify_param, endpoint_interesting

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


def persist_new(assessment_id: str, items: list[dict], cap: int = 60) -> int:
    """Add surface items not already present for this assessment (dedup by method+path).
    Capped so a chatty specialist can't flood the blackboard. Returns count added."""
    from urllib.parse import urlsplit

    from owlforge.store.db import session
    from owlforge.store.models import SurfaceItem

    def _ep(u: str) -> str:
        sp = urlsplit(u)
        return f"{sp.netloc}{sp.path}"

    added = 0
    with session() as s:
        existing_rows = s.exec(
            __import__("sqlmodel").select(SurfaceItem).where(SurfaceItem.assessment_id == assessment_id)
        ).all()
        seen = {(r.method.upper(), _ep(r.url)) for r in existing_rows}
        if len(existing_rows) >= cap:
            return 0
        for it in items:
            key = (str(it.get("method", "GET")).upper(), _ep(it["url"]))
            if key in seen:
                continue
            seen.add(key)
            s.add(SurfaceItem(id=f"surf_{secrets.token_hex(5)}", assessment_id=assessment_id,
                              url=it["url"], method=it.get("method", "GET"),
                              params=it.get("params", []), source=it.get("source", "discovered")))
            added += 1
            if len(existing_rows) + added >= cap:
                break
        if added:
            s.commit()
    return added


_HIGH_PARAM = ("category", "filter", "search", "query", "term", "keyword", "sort", "q",
               "id", "productid", "postid", "userid", "url", "redirect", "file", "path")


def _interest(it: dict) -> str:
    if endpoint_interesting(it.get("url", "")):
        return "HIGH"
    for pm in it.get("params", []):
        if any(k in str(pm).lower() for k in _HIGH_PARAM):
            return "HIGH"
    return "med"


def _classes(it: dict) -> list[str]:
    out: set[str] = set()
    for pm in it.get("params", []):
        out |= classify_param(pm)
    return sorted(out)


def render_inventory(inventory: list[dict], limit: int = 40) -> str:
    """Compact, classified inventory for the agent/report — params + vuln-classes +
    interest, highest-interest first (spec §3.1/§3.3)."""
    def _key(it):
        return (0 if _interest(it) == "HIGH" else 1, 0 if it.get("params") else 1)

    ordered = sorted(inventory, key=_key)
    lines = []
    for it in ordered[:limit]:
        params = it.get("params") or []
        pstr = ", ".join(params) if params else "(no params)"
        cls = _classes(it)
        tag = f"  classes: {', '.join(cls)}" if cls else ""
        itag = "  !HIGH" if _interest(it) == "HIGH" else ""
        lines.append(f"- {it['method']} {it['url']}  params: {pstr}{tag}  [{it['source']}]{itag}")
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


_ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".map",
              ".ico", ".gif", ".webp", ".ttf", ".mp4", ".json")
# path prefixes that strongly indicate a real (often API) route worth testing
_API_HINT = (r"api", r"rest", r"graphql", r"graphiql", r"v\d+", r"internal", r"admin",
             r"auth", r"oauth2?", r"login", r"logout", r"users?", r"accounts?", r"orders?",
             r"cart", r"checkout", r"payments?", r"search", r"upload", r"download", r"session")
_API_PREFIX_RE = "(?:" + "|".join(_API_HINT) + ")"


def _clean_js_path(p: str) -> str:
    """Normalise a path captured from JS: drop query + template placeholders + trailing /."""
    p = p.split("${", 1)[0].split("?", 1)[0].split("#", 1)[0].rstrip("/")
    return p


def extract_js_endpoints(origin: str, js: str) -> tuple[list[dict], set[str]]:
    """From a JS bundle, recover API routes the app actually calls: path?query literals,
    fetch/axios/XHR/jQuery call URLs (incl. template literals and absolute API hosts),
    and API-prefixed path literals. Regex-based (best-effort), plus loose param names."""
    import re

    js = js or ""
    items: dict[tuple, set] = {}

    def add(url: str, method: str = "GET", params=()) -> None:
        items.setdefault((url, method), set()).update(params)

    def add_raw(raw: str, method: str = "GET", params=()) -> None:
        raw = raw.strip()
        if raw.startswith(("http://", "https://")):
            pr = urlparse(raw)
            if not pr.netloc:
                return
            path = _clean_js_path(pr.path)
            if path.lower().endswith(_ASSET_EXT):
                return
            add(f"{pr.scheme}://{pr.netloc}{path}", method, params)
        elif raw.startswith("/") and not raw.startswith("//"):
            path = _clean_js_path(raw)
            if len(path) > 1 and not path.lower().endswith(_ASSET_EXT):
                add(origin + path, method, params)

    # 1) path?query literals -> precise endpoint + params (quotes incl backtick)
    for m in re.finditer(r"""["'`](/[A-Za-z0-9_\-./]+)\?([A-Za-z0-9_\-=&%${}.]+)["'`]""", js):
        keys = sorted({k for k in re.findall(r"([A-Za-z_][A-Za-z0-9_]{0,30})=", m.group(2))})
        add_raw(m.group(1), "GET", keys)

    # 2) XHR: .open("METHOD","URL")
    for m in re.finditer(r"""\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]""", js, re.I):  # noqa: E501
        add_raw(m.group(2), m.group(1).upper())

    # 3) fetch(...) / axios.method(...) / $.get|post|ajax(...) call URLs
    for m in re.finditer(r"""(?:fetch|axios(?:\.(get|post|put|delete|patch))?|\$\.(get|post|ajax))\s*\(\s*\{?[^)]*?["'`]([^"'`]+)["'`]""", js, re.I):  # noqa: E501
        verb = (m.group(1) or m.group(2) or "GET").upper()
        if verb == "AJAX":
            verb = "GET"
        add_raw(m.group(3), verb)

    # 4) API-prefixed paths anywhere (incl. inside template strings / absolute URLs)
    for m in re.finditer(r"""((?:https?://[A-Za-z0-9.\-]+(?::\d+)?)?/""" + _API_PREFIX_RE + r"""[A-Za-z0-9_\-./${}]*)""", js, re.I):  # noqa: E501
        add_raw(m.group(1))

    # 5) loose param names anywhere (?x= or &x=)
    loose = {m.group(1) for m in re.finditer(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,30})=", js)}
    out = [{"url": url, "method": method, "params": sorted(ps), "source": "js"}
           for (url, method), ps in items.items()]
    return out, loose


def js_recon(
    target: str,
    request_fn: RequestFn,
    max_js: int = 12,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    origin = _origin(target)
    r = request_fn("GET", target) or {}
    main_html = r.get("body", "") or ""
    srcs = extract_script_srcs(target, main_html)
    endpoints: list[dict] = []
    loose_params: set[str] = set()
    transport_text = main_html
    for src in srcs[:max_js]:
        jr = request_fn("GET", src) or {}
        jsbody = jr.get("body", "") or ""
        transport_text += "\n" + jsbody
        eps, loose = extract_js_endpoints(origin, jsbody)
        endpoints.extend(eps)
        loose_params |= loose

    # transport detection: WebSocket / SignalR endpoints + Blazor flags
    from owlforge.engine.transport import detect_transport, ws_surface_items
    _ws, _flags = detect_transport(target, transport_text)
    if _ws:
        endpoints.extend(ws_surface_items(_ws))
    if _flags:
        log(f"transport: detected {', '.join(sorted(_flags))}"
            + (f"; {len(_ws)} WebSocket endpoint(s)" if _ws else ""))
    # attach loose param names to the base app endpoints that have none, best-effort:
    if loose_params:
        for ep in endpoints:
            if not ep["params"]:
                # only attach to short app paths (not deep api paths) to limit noise
                if ep["url"].count("/") <= 4:
                    ep["params"] = sorted(loose_params)[:12]
    log(f"js recon: {len(srcs)} script(s), {len(endpoints)} js endpoint(s), {len(loose_params)} param name(s)")
    return endpoints


def _collect_surface(
    assessment_id: str,
    target: str,
    session_headers: dict | None,
    sandbox_client,
    *,
    max_pages: int = 25,
    browser_recon_enabled: bool = False,
    extra_seeds: list[str] | None = None,
    deep_tools: bool = True,
    log: Callable[[str], None] = lambda m: None,
) -> tuple[list[dict], str]:
    """Build (but DO NOT persist) the surface inventory for one pass, plus a
    fingerprint header line. Honors session_headers for an authenticated pass."""

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
    for _seed in (extra_seeds or []):
        try:
            inv += crawl(_seed, request_fn, max_pages=max(6, max_pages // 2), log=log)
        except Exception:
            pass
    inv += content_discovery(target, sandbox_client, session_headers, log=log)
    if deep_tools:
        inv += katana_crawl(target, sandbox_client, session_headers=session_headers, log=log)
    inv += js_recon(target, request_fn, log=log)
    inv += api_spec_discovery(target, request_fn, log=log)
    inv += graphql_probe(target, request_fn, log=log)
    if browser_recon_enabled:
        # interactive map first (drives the SPA, captures XHR/fetch + forms the static
        # crawl misses); fall back to a snapshot render only if it yields nothing.
        mapped = browser_map(target, sandbox_client, session_headers=session_headers, log=log)
        inv += mapped
        if not mapped:
            _pages = [it["url"] for it in inv if it.get("source") in ("link", "content-discovery")][:6]
            inv += browser_recon(target, sandbox_client, pages=_pages,
                                 session_headers=session_headers, log=log)
    inv = _dedup(inv)
    if deep_tools:
        inv += arjun_param_discovery(target, inv, sandbox_client, session_headers, log=log)
        inv = _dedup(inv)

    fp = fingerprint(target, request_fn)
    header = f"Fingerprint: server={fp.get('server') or '?'}; tech={', '.join(fp.get('tech') or []) or '?'}"
    waf = waf_detect(target, sandbox_client, log=log) if deep_tools else ""
    if waf:
        header += f"; waf={waf}"
    return inv, header


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
    """Single-pass recon: collect, persist, render. (See run_recon for the
    unauth -> auto-escalate -> auth pipeline.)"""
    inv, header = _collect_surface(
        assessment_id, target, session_headers, sandbox_client,
        max_pages=max_pages, browser_recon_enabled=browser_recon_enabled, log=log)
    persist(assessment_id, inv)
    text = header + "\n\n" + render_inventory(inv)
    if network_recon_enabled:
        net = network_recon(target, sandbox_client, log=log)
        if net.strip():
            text += "\n\n# Network recon (nmap, optional)\n" + net.strip()[:1500]
    return text


_EXPOSED_FILES = (".env", "config.json", "config.js", ".git/config", "credentials.json",
                  "secrets.json", "backup.sql", ".aws/credentials", "appsettings.json")


def _scan_sources(target, inventory, request_fn, log=lambda m: None):
    """Fetch the candidate sources (pages + JS + common exposed files) and scan each
    for secrets. Returns [(url, Secret), ...]. Values are kept in full (proof)."""
    from owlforge.engine import secrets as secret_scan

    base = target.rstrip("/")
    pages = [it["url"] for it in inventory
             if it.get("source") in ("link", "content-discovery", "html", "form")][:10]
    js = [it["url"] for it in inventory if it.get("url", "").endswith(".js")][:12]
    exposed = [base + "/" + f for f in _EXPOSED_FILES]
    seen_urls: list[str] = []
    for u in [base, *pages, *js, *exposed]:
        if u not in seen_urls:
            seen_urls.append(u)

    out = []
    for url in seen_urls:
        try:
            r = request_fn("GET", url) or {}
        except Exception:
            continue
        if r.get("error") or int(r.get("status") or 0) >= 400:
            continue
        for sec in secret_scan.scan_text(r.get("body") or ""):
            out.append((url, sec))
    if out:
        log(f"secret scan: {len(out)} sensitive item(s) across {len(seen_urls)} source(s)")
    return out


def discover_credentials(target, inventory, sandbox_client, request_fn, log=lambda m: None):
    """Return (session_headers, provenance) for the first USABLE credential leaked in
    unauth artifacts — for auto-escalation to authenticated recon. Secret values are
    never put in the provenance string (only where it was found)."""
    from urllib.parse import urlparse

    from owlforge.engine import secrets as secret_scan

    for url, sec in _scan_sources(target, inventory, request_fn, log=log):
        headers = secret_scan.to_session_header(sec)
        if headers:
            where = urlparse(url).path or url
            return headers, f"{sec.kind} in {where}"
    return {}, ""


def _file_info_disclosure(assessment_id, url, sec):
    """Persist one leaked secret as an information-disclosure finding. The full value
    is the proof (evidence); success_signal lets the evidence gate re-fetch and confirm
    the secret is actually served."""
    from urllib.parse import urlparse

    from owlforge.store.db import session
    from owlforge.store.models import Finding

    path = urlparse(url).path or url
    sig = sec.value[:48]
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}",
            assessment_id=assessment_id,
            title=f"Information disclosure: {sec.kind} exposed in {path}",
            severity=sec.severity,
            endpoint=url,
            method="GET",
            technical_analysis=(f"A {sec.kind} is served in the response body of {url}. "
                                "Sensitive material reachable by an unauthenticated client "
                                "is an information-disclosure / secrets-exposure issue."),
            proof_of_concept=f"{sec.kind} = {sec.value}\ncontext: {sec.context}",
            impact=("Leaked credentials/keys can be reused to access the service, its data, "
                    "or connected systems, depending on the secret's scope."),
            remediation=("Remove the secret from client-served content, rotate it immediately, "
                         "and serve secrets only from server-side configuration."),
            evidence=sec.value,
            repro_url=url, repro_method="GET", success_signal=sig,
            status="candidate",
        ))
        s.commit()


def understand_secrets(assessment_id, target, inventory, request_fn, log=lambda m: None):
    """UNDERSTAND step: scan pages + JS + exposed files for secrets/sensitive info,
    FILE each as an information-disclosure finding (full value as proof), and return
    (session_headers, provenance) for the first usable credential to escalate auth."""
    from urllib.parse import urlparse

    from owlforge.engine import secrets as secret_scan

    creds: dict = {}
    prov = ""
    filed = 0
    for url, sec in _scan_sources(target, inventory, request_fn, log=log):
        _file_info_disclosure(assessment_id, url, sec)
        filed += 1
        if not creds:
            h = secret_scan.to_session_header(sec)
            if h:
                creds, prov = h, f"{sec.kind} in {urlparse(url).path or url}"
    if filed:
        log(f"understand: filed {filed} information-disclosure finding(s)")
    return creds, prov


def _same_reg_domain(a: str, b: str) -> bool:
    la, lb = a.lower().split(":")[0].split("."), b.lower().split(":")[0].split(".")
    return la[-2:] == lb[-2:] and len(la) >= 2 and len(lb) >= 2


def _apply_scope(inventory: list[dict], target: str, scope) -> list[dict]:
    """Auto-include app-reached hosts on the target's registrable domain, then drop
    anything the scope excludes. Cross-domain hosts need an explicit --scope entry."""
    if scope is None:
        return inventory
    thost = urlparse(target).netloc.lower()
    for it in inventory:
        h = urlparse(it["url"]).netloc.lower()
        if h and _same_reg_domain(h, thost):
            scope.allow_host(h)
    return [it for it in inventory if scope.in_scope(it["url"])]


def run_recon(
    assessment_id: str,
    target: str,
    sandbox_client,
    *,
    user_auth=None,
    max_pages: int = 25,
    network_recon_enabled: bool = False,
    browser_recon_enabled: bool = False,
    scope=None,
    client=None,
    log: Callable[[str], None] = lambda m: None,
) -> tuple[str, dict, str]:
    """Unified recon pipeline. ALWAYS runs unauthenticated recon first, then
    AUTO-ESCALATES to authenticated recon when credentials are available — either
    operator-supplied (user_auth) OR leaked/exposed during the unauth pass. One
    blackboard, one render. Returns (surface_text, session_headers, auth_summary)."""
    from owlforge.engine.auth import establish_session

    def _reqfn(method, url, headers=None, params=None, body=None):
        if sandbox_client is not None:
            try:
                return sandbox_client.http_request(method, url, headers=headers, params=params, body=body)
            except Exception as e:
                return {"error": str(e)}
        import httpx
        try:
            r = httpx.request(method, url, headers=headers, params=params, content=body,
                              follow_redirects=False, timeout=20.0)
            return {"status": r.status_code, "headers": dict(r.headers), "body": r.text}
        except Exception as e:
            return {"error": str(e)}

    # auto-enable browser recon for JS/SPA apps — their real surface (forms, links,
    # params) is built client-side and invisible to static HTML. Generic: any SPA.
    if not browser_recon_enabled and sandbox_client is not None:
        try:
            fp0 = fingerprint(target, _reqfn)
            if fp0.get("tech"):
                browser_recon_enabled = True
                log(f"browser recon auto-enabled (client-side framework: {', '.join(fp0['tech'])})")
        except Exception:
            pass

    # fail loudly if the target itself is unreachable (don't imply a clean 0-findings)
    _root = _reqfn("GET", target)
    if _root.get("error") or not _root.get("status"):
        log(f"WARNING: target may be UNREACHABLE — {_root.get('error') or 'no response'}. "
            "Findings will be empty because nothing could be fetched, NOT because the app is clean.")

    # pass 1: unauthenticated (always)
    log("unauth recon")
    unauth_inv, header = _collect_surface(
        assessment_id, target, {}, sandbox_client,
        max_pages=max_pages, browser_recon_enabled=browser_recon_enabled, log=log)
    unauth_inv = _apply_scope(unauth_inv, target, scope)
    unauth_keys = {(it["method"], it["url"], tuple(sorted(it["params"]))) for it in unauth_inv}

    # resolve credentials: operator-supplied first, else discovered in unauth artifacts
    session_headers: dict = {}
    auth_summary = "unauth (no credentials provided or discovered)"
    if user_auth is not None and getattr(user_auth, "mode", "unauth") != "unauth":
        session_headers = establish_session(user_auth, _reqfn, log=log)
        if session_headers:
            auth_summary = f"authenticated (operator {user_auth.mode})"
    log("understand: scanning pages/JS/files for secrets & sensitive info")
    disc_headers, prov = understand_secrets(assessment_id, target, unauth_inv, _reqfn, log=log)
    if not session_headers and disc_headers:
        session_headers = disc_headers
        auth_summary = f"authenticated (auto-escalated: {prov})"
    if not session_headers:
        from owlforge.engine.credpage import establish_from_login_page
        _lh, _lp = establish_from_login_page(target, sandbox_client, _reqfn, log=log)
        if _lh:
            session_headers = _lh
            auth_summary = f"authenticated (login-page creds: {_lp})"
    if not session_headers and client is not None and sandbox_client is not None:
        # label-free: render the login page, let the model read ANY displayed credentials
        # (no 'username:'/'password:' labels needed), then log in through the real browser
        from owlforge.engine.browserlogin import (
            browser_login_session,
            extract_displayed_credentials,
        )
        _b = target.rstrip("/")
        for _lp in ("/login", "/signin", "/sign-in", "/account/login", "/users/login",
                    "/auth/login", "/"):
            _lu = _b + _lp
            try:
                _page = sandbox_client.render(_lu, headers=None) or {}
            except Exception:
                _page = {}
            _txt = _page.get("html") or ""
            if "<form" not in _txt.lower() and "password" not in _txt.lower():
                continue
            for _c in extract_displayed_credentials(client, _txt, log=log):
                _bh, _ = browser_login_session(sandbox_client, _lu, _c["username"],
                                               _c["password"], target,
                                               check_url=_b + "/my-account", log=log)
                if _bh:
                    session_headers = _bh
                    auth_summary = "authenticated (model-read displayed creds, browser login)"
                    log(f"auth: logged in as '{_c['username']}' using credentials shown on {_lp}")
                    break
            if session_headers:
                break

    inv = unauth_inv
    # pass 2: authenticated (only if a session was resolved)
    if session_headers:
        log("auth recon (escalated) — re-mapping the logged-in surface")
        _b = target.rstrip("/")
        _seeds = [_b + s for s in ("/my-account", "/account", "/dashboard", "/profile",
                                   "/orders", "/admin", "/settings", "/user")]
        auth_inv, _ = _collect_surface(
            assessment_id, target, session_headers, sandbox_client,
            max_pages=max_pages, browser_recon_enabled=browser_recon_enabled,
            extra_seeds=_seeds, log=log, deep_tools=False)
        for it in auth_inv:
            key = (it["method"], it["url"], tuple(sorted(it["params"])))
            if key not in unauth_keys:
                it["source"] = f"auth/{it.get('source', 'link')}"  # mark authenticated-only surface
        inv = _apply_scope(_dedup(unauth_inv + auth_inv), target, scope)

    # passive configuration/observational checks (deterministic, session-aware)
    try:
        from owlforge.engine.passive import passive_scan

        def _sreq(method, url, headers=None, params=None, body=None):
            hdrs = {**(session_headers or {}), **(headers or {})} or None
            return _reqfn(method, url, headers=hdrs, params=params, body=body)

        passive_scan(assessment_id, target, inv, _sreq, log=log)
    except Exception as e:
        log(f"passive scan failed: {e}")

    persist(assessment_id, inv)
    text = header + "\n\n" + render_inventory(inv)
    if network_recon_enabled:
        net = network_recon(target, sandbox_client, log=log)
        if net.strip():
            text += "\n\n# Network recon (nmap, optional)\n" + net.strip()[:1500]
    return text, session_headers, auth_summary

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


def _arjun_params(data) -> list[str]:
    """Collect parameter names from arjun's JSON, tolerant of version differences."""
    found: list[str] = []
    if isinstance(data, dict):
        if isinstance(data.get("params"), list):
            found += [str(x) for x in data["params"]]
        for v in data.values():
            if isinstance(v, dict) and isinstance(v.get("params"), list):
                found += [str(x) for x in v["params"]]
    elif isinstance(data, list):
        for v in data:
            if isinstance(v, dict) and isinstance(v.get("params"), list):
                found += [str(x) for x in v["params"]]
    return [p for p in found if p]


def arjun_param_discovery(target, inventory, sandbox_client, session_headers=None,
                          log: Callable[[str], None] = lambda m: None, cap: int = 6) -> list[dict]:
    """Brute-force HIDDEN parameters on a few GET endpoints with arjun (in-sandbox).
    Reveals params that feed injection/IDOR but never appear in links or forms. Bounded;
    degrades silently if arjun is not in the image."""
    if sandbox_client is None:
        return []
    import json
    from urllib.parse import urlparse
    cand, seen = [], set()
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "GET":
            continue
        if it.get("source") not in ("link", "content-discovery", "html", "api-spec",
                                    "form", "browser-form"):
            continue
        u = it.get("url", "")
        if not u or u in seen:
            continue
        seen.add(u)
        cand.append(u)
        if len(cand) >= cap:
            break
    if not cand:
        return []
    hdr = "".join(f" -H '{k}: {v}'" for k, v in (session_headers or {}).items())
    out: list[dict] = []
    for i, u in enumerate(cand):
        of = f"/workspace/arjun_{i}.json"
        cmd = (f"arjun -u '{u}' -m GET -q -t 10 -oJ {of}{hdr} >/dev/null 2>&1; "
               f"cat {of} 2>/dev/null")
        try:
            r = sandbox_client.exec(cmd, timeout_ms=120_000)
        except Exception as e:
            log(f"arjun error: {e}")
            break
        txt = (getattr(r, "stdout", "") or "").strip()
        if not txt:
            if getattr(r, "exit_code", 0) == 127 or "not found" in (getattr(r, "stderr", "") or "").lower():
                log("arjun not available in the sandbox image (skip)")
                return []
            continue
        try:
            params = _arjun_params(json.loads(txt))
        except Exception:
            continue
        if params:
            pr = urlparse(u)
            out.append({"url": f"{pr.scheme}://{pr.netloc}{pr.path}", "method": "GET",
                        "params": sorted(set(params)), "source": "arjun"})
    if out:
        log(f"arjun: discovered hidden param(s) on {len(out)} endpoint(s)")
    return out


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


def katana_crawl(
    target: str,
    sandbox_client,
    session_headers: dict | None = None,
    depth: int = 2,
    time_s: int = 90,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    """Deep JS-aware crawl with katana (in-sandbox). Complements the static crawler and
    the interactive map: katana parses JS/HTML, follows links, and surfaces endpoints the
    regex crawler misses. Same-origin, bounded depth + wall-clock. Carries auth. Read-only
    (GET crawl). Best-effort: empty list if katana isn't installed or errors."""
    if sandbox_client is None:
        return []
    base = target.rstrip("/")
    hdr = "".join(f" -H '{k}: {v}'" for k, v in (session_headers or {}).items())
    cmd = (
        f"katana -u {base} -silent -jsonl -jc -d {int(depth)} -c 10 -ct {int(time_s)} "
        f"-fs fqdn{hdr} 2>/dev/null"
    )
    try:
        r = sandbox_client.exec(cmd, timeout_ms=(time_s + 30) * 1000)
    except Exception as e:
        log(f"katana error: {e}")
        return []
    import json as _json
    origin = _origin(target)
    out: list[dict] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = _json.loads(line)
        except Exception:
            continue
        req = rec.get("request", {}) if isinstance(rec, dict) else {}
        url = req.get("endpoint") or rec.get("endpoint") or ""
        if not url or _origin(url) != origin:
            continue
        method = (req.get("method") or "GET").upper()
        params = sorted(parse_qs(urlparse(url).query).keys())
        out.append({"url": _strip(url), "method": method, "params": params,
                    "source": "katana"})
    out = _dedup(out)
    log(f"katana: {len(out)} endpoint(s)")
    return out


def waf_detect(target: str, sandbox_client, log: Callable[[str], None] = lambda m: None) -> str:
    """Detect a WAF/CDN in front of the target with wafw00f (in-sandbox). Returns a short
    label for the fingerprint header (and informs the bypass loop). '' if none/unavailable."""
    if sandbox_client is None:
        return ""
    cmd = (f"wafw00f {target} -f json -o /workspace/waf.json >/dev/null 2>&1; "
           "cat /workspace/waf.json 2>/dev/null")
    try:
        r = sandbox_client.exec(cmd, timeout_ms=60_000)
        import json as _json
        data = _json.loads(r.stdout or "[]")
    except Exception as e:
        log(f"wafw00f error: {e}")
        return ""
    if isinstance(data, dict):
        data = [data]
    names: list[str] = []
    for d in data or []:
        if d.get("detected") and d.get("firewall") and d["firewall"].lower() != "none":
            fw = d["firewall"]
            man = d.get("manufacturer") or ""
            names.append(f"{fw}" + (f" ({man})" if man and man != fw else ""))
    if names:
        log(f"waf: {', '.join(names)}")
        return ", ".join(dict.fromkeys(names))
    return ""


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
        from owlforge.engine.apispec import openapi_to_items
        out = openapi_to_items(spec, origin)
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


def browser_map(
    target: str,
    sandbox_client,
    session_headers: dict | None = None,
    max_pages: int = 12,
    log: Callable[[str], None] = lambda m: None,
) -> list[dict]:
    """Browser-driven INTERACTIVE recon (the real-world/SPA path). Drives Chromium
    through the app via agentd /map, capturing every XHR/fetch/document request the
    JS makes plus rendered links & forms. Converts that live traffic into surface
    items -- recovering formless/JS-built API calls that static crawl never sees.
    Non-destructive (no form fills/submits). Carries the auth session."""
    if sandbox_client is None:
        log("interactive map skipped (no sandbox)")
        return []
    try:
        d = sandbox_client.map(target, headers=(session_headers or None), max_pages=max_pages)
    except Exception as e:
        log(f"interactive map error: {e}")
        return []
    if d.get("error") and not d.get("requests"):
        log(f"interactive map: {d['error']}")
        return []

    out: list[dict] = []

    def _params(u: str) -> list[str]:
        try:
            return sorted(parse_qs(urlparse(u).query).keys())
        except Exception:
            return []

    for r in d.get("requests", []):
        url = r.get("url", "")
        if not url:
            continue
        rt = r.get("type", "")
        src = "browser-xhr" if rt in ("xhr", "fetch") else "browser-nav"
        out.append({"url": _strip(url), "method": (r.get("method") or "GET").upper(),
                    "params": _params(url), "source": src})
    for f in d.get("forms", []):
        action = f.get("action", "")
        if not action:
            continue
        names = sorted({fl.get("name", "") for fl in f.get("fields", []) if fl.get("name")})
        out.append({"url": _strip(action), "method": (f.get("method") or "GET").upper(),
                    "params": names, "source": "browser-form"})
    for lnk in d.get("links", []):
        out.append({"url": _strip(lnk), "method": "GET", "params": _params(lnk),
                    "source": "browser-link"})

    out = _dedup(out)
    pages = len(d.get("pages", []))
    nxhr = sum(1 for r in d.get("requests", []) if r.get("type") in ("xhr", "fetch"))
    ws = d.get("websockets", [])
    log(f"interactive map: visited {pages} route(s), {nxhr} xhr/fetch call(s), "
        f"{len(d.get('forms', []))} form(s), {len(out)} surface item(s)"
        + (f", {len(ws)} websocket(s)" if ws else ""))
    return out


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse nuclei -jsonl output into {title, severity, url, template, evidence}."""
    import json as _json

    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = _json.loads(line)
        except Exception:
            continue
        info = d.get("info") or {}
        out.append({
            "template": d.get("template-id") or d.get("templateID") or "",
            "title": info.get("name") or d.get("template-id") or "nuclei finding",
            "severity": (info.get("severity") or "info").lower(),
            "url": d.get("matched-at") or d.get("host") or d.get("matched") or "",
            "evidence": (d.get("matched-at") or "") + " " + str(d.get("extracted-results") or ""),
        })
    return out


def nuclei_scan(assessment_id: str, target: str, sandbox_client,
                severities: str = "low,medium,high,critical",
                timeout_ms: int = 420_000, log: Callable[[str], None] = lambda m: None) -> int:
    """Run nuclei (full templates) in the sandbox as a signal source; file each hit as a
    candidate finding for the specialists to confirm/deepen. Opt-in (slower)."""
    if sandbox_client is None:
        log("nuclei skipped (no sandbox)")
        return 0
    sev = f"-severity {severities}" if severities else ""
    cmd = (f"nuclei -u {target} -jsonl -silent -disable-update-check "
           f"-timeout 10 -rate-limit 60 {sev} 2>/dev/null")
    try:
        r = sandbox_client.exec(cmd, timeout_ms=timeout_ms)
        hits = _parse_nuclei_jsonl(r.stdout or "")
    except Exception as e:
        log(f"nuclei error: {e}")
        return 0

    import secrets as _secrets

    from owlforge.store.db import session
    from owlforge.store.models import Finding

    filed = 0
    seen: set[tuple] = set()
    with session() as s:
        for h in hits:
            key = (h["template"], h["url"])
            if key in seen:
                continue
            seen.add(key)
            s.add(Finding(
                id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
                title=f"nuclei: {h['title']}", severity=h["severity"] if h["severity"] != "info" else "low",
                endpoint=h["url"], method="GET",
                technical_analysis=f"nuclei template '{h['template']}' matched at {h['url']}.",
                proof_of_concept=h["evidence"].strip()[:300], evidence=h["evidence"].strip()[:500],
                impact="See the nuclei template description for this class of issue.",
                remediation="Triage the matched template; confirm and remediate per its guidance.",
                status="candidate", confidence="medium",
                validation_note=f"nuclei signal ({h['template']})"))
            filed += 1
        if filed:
            s.commit()
    log(f"nuclei: {len(hits)} match(es), {filed} finding(s) filed")
    return filed

