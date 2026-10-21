"""Client-side checks: postMessage origin validation + subdomain takeover.

* postMessage: a 'message' listener that doesn't check event.origin can be driven by any
  site. We statically scan the app's JS for a message listener with no 'origin' reference
  nearby and file a CANDIDATE (static analysis -> manual confirmation).
* Subdomain takeover: a host whose DNS CNAME points to a third-party service that no longer
  serves it (fingerprint in the page) can be claimed by an attacker -> full control of that
  (trusted) origin. CNAME + service fingerprint is a sound, VALIDATED signal.

DOM clobbering is not auto-confirmable generically and is left to manual review.
"""

from __future__ import annotations

import re
import secrets as _secrets
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

_MSG_RE = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|\bonmessage\s*=", re.I)
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)

# third-party services whose "unclaimed" page fingerprint indicates a takeover
_TAKEOVER = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("amazonaws.com", "NoSuchBucket"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudfront.net", "ERROR: The request could not be satisfied"),
    ("wordpress.com", "Do you want to register"),
    ("pantheonsite.io", "The gods are wise"),
    ("fastly.net", "Fastly error: unknown domain"),
    ("zendesk.com", "Help Center Closed"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("ghost.io", "The thing you were looking for is no longer here"),
    ("readthedocs.io", "unknown to Read the Docs"),
]


def _get(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}) or {}
    except Exception:
        return {}


def _file(assessment_id, title, severity, status, endpoint, analysis, poc, note, conf="high"):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=title, severity=severity, status=status, confidence=conf,
            endpoint=endpoint, method="GET", technical_analysis=analysis,
            proof_of_concept=poc, impact="See description.",
            remediation="", validation_note=note))
        s.commit()


def _js_sources(sandbox, pages, headers, cap=12):
    """Yield (url, js_text) for inline + external scripts across a few pages."""
    out, seen = [], set()
    for page in pages:
        r = _get(sandbox, page, headers)
        html = r.get("body") or ""
        for inline in _INLINE.findall(html):
            out.append((page, inline))
        for src in _SCRIPT_SRC.findall(html):
            u = urljoin(r.get("final_url", page), src)
            if u in seen or urlsplit(u).netloc != urlsplit(page).netloc:
                continue
            seen.add(u)
            jr = _get(sandbox, u, headers)
            out.append((u, jr.get("body") or ""))
            if len(out) >= cap:
                return out
    return out


def _listener_without_origin(text):
    for m in _MSG_RE.finditer(text):
        if "origin" not in text[m.start():m.start() + 700].lower():
            return True
    return False


def postmessage_scan(assessment_id, inventory, sandbox, session_headers,
                     log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None:
        return 0
    pages = list(dict.fromkeys(it["url"] for it in inventory if it.get("url")
                               and it.get("source") in ("link", "content-discovery", "browser-nav")))[:5]
    if not pages:
        return 0
    filed, hit = 0, set()
    for url, js in _js_sources(sandbox, pages, session_headers):
        if url in hit or not js:
            continue
        if _listener_without_origin(js):
            hit.add(url)
            _file(assessment_id,
                  "postMessage handler without origin validation", "medium", "candidate", url,
                  f"A 'message' event listener in {url} does not appear to validate "
                  "event.origin, so any page can send it messages. Verify the handler and "
                  "its data sinks (DOM write / eval / navigation).",
                  "addEventListener('message', …) with no event.origin check nearby",
                  "static analysis — needs manual verification", conf="low")
            filed += 1
    if filed:
        log(f"client-side: {filed} postMessage handler(s) without an origin check (candidate)")
    return filed


def _cname(sandbox, host):
    try:
        r = sandbox.exec(f"dig +short CNAME {host} 2>/dev/null || host -t CNAME {host} 2>/dev/null",
                         timeout_ms=15_000)
        return (getattr(r, "stdout", "") or "").lower()
    except Exception:
        return ""


def subdomain_takeover_scan(assessment_id, inventory, sandbox, session_headers, target="",
                            log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None:
        return 0
    hosts = set()
    if target:
        hosts.add(urlsplit(target).netloc.split(":")[0])
    for it in inventory:
        h = urlsplit(it.get("url") or "").netloc.split(":")[0]
        if h:
            hosts.add(h)
    filed = 0
    for host in list(hosts)[:30]:
        cname = _cname(sandbox, host)
        svc = next((s for s, _ in _TAKEOVER if s in cname), None)
        if not svc:
            continue
        fp = dict(_TAKEOVER)[svc]
        r = _get(sandbox, f"https://{host}/", session_headers) or _get(sandbox, f"http://{host}/", session_headers)
        if fp.lower() in (r.get("body") or "").lower():
            _file(assessment_id, "Subdomain takeover", "high", "validated", f"https://{host}/",
                  f"{host} has a dangling DNS CNAME to {svc} ({cname.strip()}) and the service "
                  f"returns its 'unclaimed' page ({fp!r}). An attacker can claim it and control "
                  "this trusted origin (serve content, steal cookies scoped to the domain, "
                  "bypass CORS trust).",
                  f"CNAME {host} -> {svc}; page shows {fp!r}",
                  "dangling CNAME + unclaimed-service fingerprint (deterministic)")
            filed += 1
    if filed:
        log(f"client-side: {filed} subdomain takeover(s) confirmed")
    return filed
