"""Authenticated API-surface discovery.

An authenticated scan of a modern API app (crAPI) finds nothing because the object endpoints
where BOLA/IDOR live (/identity/api/v2/vehicle/{id}, /workshop/api/shop/orders, ...) appear in
the JS bundle only as RELATIVE literals ("api/v2/vehicle/...") whose service prefix (/identity,
/community, /workshop) is applied at runtime — so neither the crawler nor the access-control
scanner ever sees the real path. This recovers them: grep the API path literals out of the JS
bundles IN the sandbox (so the 200 KB http-response cap never truncates a big bundle), probe each
under the app's gateway prefixes with the authenticated session, and persist the ones that
resolve, so the access-control / IDOR scanners have real objects to test.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from urllib.parse import urlsplit

_ASSET = (".js", ".css", ".map", ".png", ".jpg", ".svg", ".ico", ".woff", ".woff2", ".json")
_TEMPLATE = re.compile(r"\{[^}]{1,30}\}|:[A-Za-z_]\w{0,30}|\$\{[^}]{1,30}\}")
# grep (ERE) pattern run inside the sandbox against the full bundle
_GREP = r"(api|rest|graphql|v[0-9]+)/[A-Za-z0-9/_.{}:$-]{2,80}"
# common microservice / app-section names to probe as gateway prefixes
_SECTIONS = ("identity", "community", "workshop", "api", "gateway", "auth", "user", "users",
             "account", "accounts", "shop", "store", "admin", "forum", "blog", "core",
             "services", "backend", "app", "v1", "v2")


def _req(sandbox, method, url, headers):
    try:
        return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                    body=None, follow_redirects=False) or {}
    except TypeError:
        try:
            return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                        body=None) or {}
        except Exception:
            return {}
    except Exception:
        return {}


def _bundle_urls(inventory, sandbox, origin) -> list[str]:
    urls, seen = [], set()

    def add(u):
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    for it in inventory or []:
        u = it.get("url") or ""
        if u.lower().endswith(".js"):
            add(u)
    idx = _req(sandbox, "GET", origin + "/", None).get("body") or ""
    for m in re.finditer(r'src=["\']([^"\']+\.js)["\']', idx):
        p = m.group(1)
        add(p if p.startswith("http") else origin + ("" if p.startswith("/") else "/") + p)
    return urls[:6]


def _api_literals(sandbox, bundle_urls) -> list[str]:
    """API path literals grepped from the full bundle IN the sandbox (no 200 KB truncation)."""
    lits, seen = [], set()
    for url in bundle_urls:
        cmd = (f"curl -s --max-time 25 {shlex.quote(url)} | grep -oE {shlex.quote(_GREP)} "
               "| sort -u | head -400")
        try:
            out = sandbox.exec(cmd, timeout_ms=45_000).stdout or ""
        except Exception:
            out = ""
        for line in out.splitlines():
            p = line.strip().strip("\"'`").lstrip("/").rstrip("/")
            if not p or p.lower().endswith(_ASSET):
                continue
            probe = _TEMPLATE.sub("1", p)            # {id}/:id/${id} -> 1 so the path resolves
            if probe not in seen:
                seen.add(probe)
                lits.append(probe)
    return lits


def _prefixes(inventory, sandbox, origin) -> list[str]:
    cands = list(_SECTIONS)
    for it in inventory or []:
        seg = urlsplit(it.get("url") or "").path.strip("/").split("/")[0].lower()
        if seg and seg.isalpha() and 2 <= len(seg) <= 24 and seg not in cands:
            cands.append(seg)
    live = []
    for seg in cands:
        st = int(_req(sandbox, "GET", f"{origin}/{seg}", None).get("status") or 0)
        if st and st != 404:
            live.append(seg)
        if len(live) >= 12:
            break
    return live


def discover_api_endpoints(assessment_id, inventory, sandbox, target, session_headers=None,
                           log: Callable[[str], None] = lambda m: None, cap: int = 200,
                           max_probes: int = 180) -> int:
    """Recover authenticated API object endpoints from the JS and persist the ones that resolve
    with the session. Returns the count added to the surface."""
    if sandbox is None:
        return 0
    u = urlsplit(target)
    origin = f"{u.scheme}://{u.netloc}"
    literals = _api_literals(sandbox, _bundle_urls(inventory, sandbox, origin))
    if not literals:
        return 0
    prefixes = _prefixes(inventory, sandbox, origin)
    existing = {(it.get("url") or "").rstrip("/") for it in inventory or []}
    found, seen, probes = [], set(), 0
    for lit in literals:
        for pre in [""] + prefixes:
            url = f"{origin}/{pre + '/' if pre else ''}{lit}"
            key = url.rstrip("/")
            if key in seen or key in existing:
                continue
            seen.add(key)
            if len(found) >= cap or probes >= max_probes:
                break
            probes += 1
            r = _req(sandbox, "GET", url, session_headers)
            st = int(r.get("status") or 0)
            body = (r.get("body") or "")[:200].lower()
            if st and st not in (404, 0, 502, 503) and "<html" not in body:
                found.append({"url": url, "method": "GET", "params": [], "source": "js-api"})
    if not found:
        return 0
    try:
        from owlforge.engine.recon import persist_new
        added = persist_new(assessment_id, found, cap=400)
    except Exception:
        added = 0
    if added:
        log(f"api-surface: recovered {added} authenticated API endpoint(s) from the JS bundle")
    return added
