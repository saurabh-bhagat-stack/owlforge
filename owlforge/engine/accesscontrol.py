"""Authenticated access-control / IDOR scan (recon-spec: broken object-/function-level authz).

Deterministically probes the authorization boundary on authenticated object/account
endpoints with a THREE-way differential (owner identity + other identity + anonymous):

  * owner A fetches the resource (baseline, must be a real 200 with content);
  * if anonymous ALSO gets the same content -> the resource is PUBLIC -> NOT a finding
    (this is what stops the classic false positive: a public catalog item returns 200 to
    everyone);
  * otherwise the resource is protected. If a DIFFERENT authenticated identity can still
    read A's copy -> broken access control (horizontal IDOR/BOLA, or vertical privilege
    escalation when the other identity's role is lower); if an account-scoped resource is
    readable anonymously -> missing authentication.

Object-ID *enumeration* is deliberately NOT used on its own (public collections return 200
legitimately); only the boundary differential auto-files a finding. Model-independent.
"""

from __future__ import annotations

import re
import secrets as _secrets
from collections.abc import Callable

from owlforge.engine.classify import OBJECT_ID, classify_param, endpoint_interesting

_AUTHED = ("/my-account", "/account", "/dashboard", "/profile", "/orders", "/order",
           "/admin", "/settings", "/user", "/users", "/me", "/billing", "/invoice",
           "/cart", "/wishlist", "/messages", "/inbox")
_NUM_SEG = re.compile(r"/\d{1,}(?:[/?]|$)")
_UUID = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

_ROLE_RANK = {"admin": 3, "superuser": 3, "root": 3, "user": 2, "anonymous": 1, "anon": 1}


def _is_object_endpoint(it: dict) -> bool:
    url = it.get("url", "") or ""
    low = url.lower()
    if any(OBJECT_ID in classify_param(p) for p in (it.get("params") or [])):
        return True
    if _NUM_SEG.search(url) or _UUID.search(url):
        return True
    if any(seg in low for seg in _AUTHED):
        return True
    return endpoint_interesting(url)


def _object_endpoints(inventory: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in inventory:
        url = it.get("url")
        if not url:
            continue
        key = ((it.get("method") or "GET").upper(), url)
        if key in seen or not _is_object_endpoint(it):
            continue
        seen.add(key)
        out.append({"url": url, "method": (it.get("method") or "GET").upper()})
    return out


def _acct_scoped(url: str) -> bool:
    return any(seg in (url or "").lower() for seg in _AUTHED)


def _get(sandbox, method, url, headers):
    try:
        return sandbox.http_request(method or "GET", url, headers=headers or {},
                                    params=None, body=None) or {}
    except Exception:
        return {}


def _usable(r: dict) -> bool:
    return int(r.get("status") or 0) == 200 and len(r.get("body") or "") >= 50


def _file(assessment_id, url, method, note, severity="high"):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Broken access control (IDOR / missing authorization)",
            severity=severity, status="validated", confidence="high",
            endpoint=url, method=method, technical_analysis=note,
            proof_of_concept=f"{method} {url} — {note}",
            impact="A user can read or act on another user's data or privileged "
                   "functionality by requesting it directly.",
            remediation="Enforce per-identity, per-object authorization on every request, "
                        "server-side; deny by default. Do not rely on unguessable IDs.",
            validation_note="confirmed by owner/other-identity/anonymous differential "
                            "(deterministic)"))
        s.commit()


def access_control_scan(assessment_id, inventory, sandbox, session_headers, identities,
                        log: Callable[[str], None] = lambda m: None) -> int:
    """Run the boundary differential over authenticated object/account endpoints and
    auto-file confirmed broken-access-control findings. Returns the count filed."""
    if sandbox is None:
        return 0
    from owlforge.engine.validate import _looks_like_login, _similar

    authed = [i for i in (identities or []) if i.get("headers")]
    if not authed and session_headers:
        authed = [{"label": "session", "role": "user", "headers": session_headers}]
    if not authed:
        return 0
    # baseline = highest-privilege identity (so a lower one reading it = clear escalation)
    authed = sorted(authed, key=lambda i: _ROLE_RANK.get((i.get("role") or "user").lower(), 2),
                    reverse=True)
    base = authed[0]
    others = authed[1:]

    targets = _object_endpoints(inventory)
    if not targets:
        log("access-control: no object/account endpoints in the authed surface")
        return 0
    log(f"access-control: boundary-testing {min(len(targets), 30)} authed endpoint(s)"
        + (f" across {len(authed)} identities + anon" if others else " (authed vs anon)"))

    filed = 0
    for t in targets[:30]:
        url, method = t["url"], t["method"]
        a = _get(sandbox, method, url, base.get("headers"))
        if not _usable(a):
            continue
        abody = a["body"]
        anon = _get(sandbox, method, url, {})
        anon_same = (_usable(anon) and _similar(abody, anon.get("body", ""))
                     and not _looks_like_login(anon.get("body", "")))
        if anon_same:
            # public to everyone -> only a problem if it's an account-scoped resource
            if _acct_scoped(url):
                _file(assessment_id, url, method,
                      "account-scoped resource is readable anonymously "
                      "(missing authentication / broken access control)")
                filed += 1
            continue  # plain public page -> not a finding (avoids the catalog false positive)
        # resource is protected (anon denied/different). Does another identity read A's copy?
        for b in others:
            r = _get(sandbox, method, url, b.get("headers"))
            if _usable(r) and _similar(abody, r.get("body", "")) \
                    and not _looks_like_login(r.get("body", "")):
                brank = _ROLE_RANK.get((b.get("role") or "user").lower(), 2)
                arank = _ROLE_RANK.get((base.get("role") or "user").lower(), 2)
                kind = ("vertical privilege escalation" if brank < arank
                        else "horizontal access / IDOR")
                _file(assessment_id, url, method,
                      f"broken access control ({kind}): identity '{b.get('label')}' "
                      f"(role {b.get('role')}) reads the protected resource served to "
                      f"'{base.get('label')}'; anonymous access is denied")
                filed += 1
                break

    if filed:
        log(f"access-control: {filed} broken-access-control finding(s) confirmed")
    else:
        log("access-control: authorization boundary held on the tested endpoints")
    return filed
