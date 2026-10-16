"""Parameter / endpoint classification (recon spec §3.1).

Deterministic routing: map each discovered input to the vuln classes worth testing,
so the orchestrator can dispatch focused specialist agents. A param is a default
injection candidate (sqli/xss); name heuristics add class-specific routes.
"""

from __future__ import annotations

SQLI = "sqli"
XSS = "xss"
PATH = "path_traversal"
OBJECT_ID = "access_control"
SSRF = "ssrf_redirect"
CSRF = "csrf"

_ID = ("id", "productid", "userid", "orderid", "accountid", "docid", "itemid", "pid",
       "uid", "gid", "oid", "objectid", "invoiceid", "ticketid", "fileid")
_URL = ("url", "uri", "redirect", "redir", "next", "return", "returnurl", "callback",
        "dest", "destination", "continue", "goto", "feed", "site")
_PATH = ("file", "filename", "path", "page", "template", "include", "download",
         "doc", "document", "lang", "dir", "folder", "load", "view")
# (free-text names are already covered by the default sqli/xss tags)


def classify_param(name: str) -> set[str]:
    n = (name or "").lower().strip()
    tags: set[str] = {SQLI, XSS}  # any param is a default injection candidate
    if any(k == n or n.endswith(k) for k in _ID):
        tags.add(OBJECT_ID)
    if any(k in n for k in _URL):
        tags.add(SSRF)
    if any(k in n for k in _PATH):
        tags.add(PATH)
    return tags


_INTEREST = ("admin", "internal", "debug", "api", "upload", "download", "export",
             "import", "proxy", "fetch", "redirect", "config", "console", "actuator",
             "graphql", "webhook", "callback", "execute", "run", "private", "secret")


def endpoint_interesting(url: str) -> bool:
    u = (url or "").lower()
    return any(k in u for k in _INTEREST)
