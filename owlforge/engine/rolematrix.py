"""Per-role capability matrix — function-level authorization by role hierarchy.

access_control_scan compares a resource across identities (owner vs other vs anon) and needs
a higher-privilege identity to establish the baseline. This pass is complementary: it infers
the REQUIRED privilege from the endpoint's path (admin / manage / internal / console / …)
and checks, across the role hierarchy, whether a LOWER-privilege actor (a normal user, or
anonymous) can still reach it — classic forced-browsing to privileged functionality. It
fires even when the operator only has a normal account, which the owner/other differential
cannot catch.

It builds an explicit role x endpoint access matrix (logged for visibility) and files a
candidate for each privileged-path endpoint a below-privilege actor can reach. Candidate,
because the required privilege is inferred from the path — a human confirms intent. Read-only
(GET) probing; no state change.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable

# privileged path segments (matched on a path boundary, not as a bare substring)
_PRIV_PATH = ("admin", "administrator", "manage", "management", "manager", "internal",
              "backoffice", "back-office", "console", "superuser", "staff", "moderator",
              "config", "settings/system", "sudo", "privileged", "root", "ops")
_ROLE_RANK = {"admin": 3, "administrator": 3, "superuser": 3, "root": 3, "staff": 3,
              "manager": 3, "moderator": 3, "ops": 3,
              "user": 2, "member": 2, "customer": 2,
              "anonymous": 1, "anon": 1, "guest": 1}
_PRIV_RANK = 3


def _privileged_path(url: str) -> bool:
    low = (url or "").lower()
    return any((f"/{seg}" in low) for seg in _PRIV_PATH)


def _priv_endpoints(inventory):
    seen, out = set(), []
    for it in inventory or []:
        url = it.get("url") or ""
        if (it.get("method") or "GET").upper() != "GET":
            continue
        if not url or url in seen or not _privileged_path(url):
            continue
        seen.add(url)
        out.append(url)
    return out


def _get(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}, params=None, body=None) or {}
    except Exception:
        return {}


def _rank(role):
    return _ROLE_RANK.get((role or "user").lower(), 2)


def _file(assessment_id, url, actor_label, actor_role, anon):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    who = ("an UNAUTHENTICATED visitor" if anon
           else f"a lower-privilege role ('{actor_label}', role {actor_role})")
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=("Privileged endpoint reachable without authentication" if anon
                   else "Privileged endpoint reachable by a lower-privilege role "
                        "(missing function-level authorization)"),
            severity="high", status="candidate", confidence="medium",
            endpoint=url, method="GET",
            technical_analysis=(
                f"The path of {url} signals privileged/administrative functionality, yet {who} "
                "received a usable response (HTTP 200 with real content, not a login page). If "
                "this functionality is meant to require an elevated role, the function-level "
                "authorization check is missing. Confirm the intended audience of the endpoint."),
            proof_of_concept=f"GET {url} as {actor_label} -> 200 with content",
            impact="Forced browsing to privileged/admin functionality: a normal user (or "
                   "anonymous visitor) can reach administrative pages or actions.",
            remediation="Enforce a server-side role check on every privileged route (deny by "
                        "default); never gate admin functionality by UI visibility or URL obscurity.",
            validation_note="privileged-path endpoint reachable by a below-privilege actor "
                            "(role-hierarchy differential) — verify intended access"))
        s.commit()


def capability_matrix_scan(assessment_id, inventory, sandbox, session_headers, identities,
                           log: Callable[[str], None] = lambda m: None, cap: int = 20) -> int:
    """Build a role x privileged-endpoint access matrix and flag below-privilege access."""
    if sandbox is None:
        return 0
    from owlforge.engine.validate import _looks_like_login

    actors = [{"label": "anonymous", "role": "anonymous", "headers": {}}]
    for i in (identities or []):
        if i.get("headers"):
            actors.append(i)
    if len(actors) == 1 and session_headers:          # only anon so far
        actors.append({"label": "session", "role": "user", "headers": session_headers})

    eps = _priv_endpoints(inventory)
    if not eps:
        return 0
    log(f"role-matrix: testing {min(len(eps), cap)} privileged-path endpoint(s) across "
        f"{len(actors)} actor(s)")
    filed = 0
    for url in eps[:cap]:
        reached = []
        violator = None
        for a in actors:
            r = _get(sandbox, url, a.get("headers"))
            ok = (int(r.get("status") or 0) == 200 and len(r.get("body") or "") >= 50
                  and not _looks_like_login(r.get("body", "")))
            if ok:
                reached.append(a["label"])
                if _rank(a.get("role")) < _PRIV_RANK:
                    # prefer the lowest-privilege violator (anonymous beats a normal user)
                    if violator is None or _rank(a.get("role")) < _rank(violator.get("role")):
                        violator = a
        log(f"role-matrix: {url} reachable by: {', '.join(reached) or 'none'}")
        if violator is not None:
            anon = _rank(violator.get("role")) <= 1
            _file(assessment_id, url, violator.get("label"), violator.get("role"), anon)
            filed += 1
    if filed:
        log(f"role-matrix: {filed} privileged endpoint(s) reachable by a lower-privilege actor")
    return filed
