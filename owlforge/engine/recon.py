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


def recon_phase(
    assessment_id: str,
    target: str,
    session_headers: dict | None,
    sandbox_client,
    max_pages: int = 25,
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
    persist(assessment_id, inv)
    return render_inventory(inv)
