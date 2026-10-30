"""Object-ID-harvesting BOLA (Broken Object Level Authorization / IDOR on opaque IDs).

access_control_scan tests object endpoints that are ALREADY in the surface — i.e. identity A's
OWN objects. But the classic API BOLA (crAPI vehicle/order, most real APIs) is A requesting
*another* user's object by an opaque ID (UUID / numeric) that A never legitimately saw. This
closes that gap, read-only:

  1. Build object-endpoint TEMPLATES from the surface (a UUID/numeric path segment or an
     access_control-classified id query param becomes a {ID} slot).
  2. HARVEST id tokens from each authenticated identity's own responses, recording which identity
     each id appeared for.
  3. For a template, substitute an id that belongs to identity B ONLY into a request made as
     identity A. If A gets a usable response that ECHOES that id (so it really returned B's
     object) while an anonymous request is denied / different (so the object is not public), A
     read B's private object -> BOLA.

Needs >=2 authenticated identities (so an id provably belongs to a *different* user); with one
session access_control_scan's anon differential already applies. Model-independent; GET-only.
"""

from __future__ import annotations

import re  # noqa: E402
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from owlforge.engine.classify import OBJECT_ID, classify_param
from owlforge.engine.validate import _looks_like_login, _similar

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NUM = re.compile(r"\b\d{3,}\b")
_SLOT = "__OWLID__"            # placeholder (alnum so urlencode leaves it intact)


def _get(sandbox, method, url, headers):
    try:
        return sandbox.http_request(method, url, headers=headers or {}, params=None, body=None,
                                    follow_redirects=False) or {}
    except TypeError:
        try:
            return sandbox.http_request(method, url, headers=headers or {}, params=None,
                                        body=None) or {}
        except Exception:
            return {}
    except Exception:
        return {}


def _usable(r: dict) -> bool:
    st = int(r.get("status") or 0)
    return 200 <= st < 300 and bool(r.get("body"))


def _id_tokens(text: str) -> set[str]:
    text = text or ""
    ids: set[str] = set(_UUID.findall(text))
    # strip UUIDs first so their digit runs aren't harvested as bogus numeric ids
    nums = _NUM.findall(_UUID.sub(" ", text))
    ids |= set(nums[:80])
    return ids


def _templates(inventory: list[dict]) -> list[tuple[str, str]]:
    """(template_with_slot, method) for every GET object endpoint; the id is replaced with a slot."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for it in inventory or []:
        url = it.get("url") or ""
        if (it.get("method") or "GET").upper() != "GET" or not url:
            continue
        u = urlsplit(url)
        segs = u.path.split("/")
        for i, seg in enumerate(segs):            # id in a path segment
            if _UUID.fullmatch(seg) or (seg.isdigit() and len(seg) >= 3):
                t = segs[:]
                t[i] = _SLOT
                tmpl = urlunsplit((u.scheme, u.netloc, "/".join(t), u.query, ""))
                if (tmpl, "GET") not in seen:
                    seen.add((tmpl, "GET"))
                    out.append((tmpl, "GET"))
        q = parse_qsl(u.query)                     # id in a query param
        for k, v in q:
            if OBJECT_ID in classify_param(k) and (_UUID.fullmatch(v) or v.isdigit()):
                nq = urlencode([(k2, _SLOT if k2 == k else v2) for k2, v2 in q])
                tmpl = urlunsplit((u.scheme, u.netloc, u.path, nq, ""))
                if (tmpl, "GET") not in seen:
                    seen.add((tmpl, "GET"))
                    out.append((tmpl, "GET"))
    return out


def _file(assessment_id, url, method, a_label, b_label, oid, log):
    import secrets

    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Broken object-level authorization (BOLA / IDOR on object ID)",
            severity="high", status="validated", confidence="high", endpoint=url, method=method,
            technical_analysis=(
                f"Identity '{a_label}' retrieved the object with id {oid} — an id that belongs to a "
                f"different user ('{b_label}', the only identity whose own responses exposed it) — "
                f"at {method} {url}. The response returned that object's data and an unauthenticated "
                "request is denied, so the endpoint authorizes by authentication alone and never "
                "checks that the caller owns the requested object."),
            proof_of_concept=(
                f"id {oid} appeared only in '{b_label}'s responses; requesting it as '{a_label}' "
                f"returned the object (anonymous is denied):\n{method} {url}"),
            impact="Any authenticated user can read (and often modify) other users' objects by "
                   "iterating or guessing object IDs — mass data exposure / account takeover.",
            remediation="Enforce per-object ownership checks on every request (the authenticated "
                        "principal must own or be authorized for the specific object ID).",
            validation_note="cross-identity id substitution: an id owned by another identity was "
                            "readable by this one while anonymous access is denied (deterministic)",
            success_signal="bola"))
        s.commit()


def bola_scan(assessment_id, inventory, sandbox, identities,
              log: Callable[[str], None] = lambda m: None, target: str = "",
              max_ids: int = 8, max_templates: int = 40) -> int:
    """Harvest object IDs per identity and cross-request them to confirm BOLA. Returns findings."""
    if sandbox is None:
        return 0
    authed = [i for i in (identities or []) if i.get("headers")]
    if len(authed) < 2:
        return 0
    templates = _templates(inventory)[:max_templates]
    if not templates:
        return 0
    concrete = [it.get("url") for it in inventory
                if (it.get("method") or "GET").upper() == "GET" and it.get("url")][:60]
    seen: dict[str, set[str]] = {}                 # id -> set(identity labels it appeared for)
    for idn in authed:
        for url in concrete:
            r = _get(sandbox, "GET", url, idn["headers"])
            if _usable(r):
                for tok in _id_tokens(r.get("body", "")):
                    seen.setdefault(tok, set()).add(idn["label"])
    if not seen:
        return 0
    log(f"bola: harvested {len(seen)} object id(s) across {len(authed)} identities; "
        f"probing {len(templates)} template(s)")
    filed = 0
    done: set[str] = set()
    for tmpl, method in templates:
        for a in authed:
            for b in authed:
                if a["label"] == b["label"]:
                    continue
                b_only = [i for i, labs in seen.items()
                          if b["label"] in labs and a["label"] not in labs]
                for oid in b_only[:max_ids]:
                    url = tmpl.replace(_SLOT, str(oid))
                    if url in done:
                        continue
                    done.add(url)
                    ra = _get(sandbox, method, url, a["headers"])
                    if not _usable(ra) or str(oid) not in (ra.get("body") or ""):
                        continue                   # not a usable response that returned THAT object
                    anon = _get(sandbox, method, url, {})
                    if _usable(anon) and _similar(ra.get("body", ""), anon.get("body", "")):
                        continue                   # object is public -> not a boundary break
                    if _looks_like_login(ra.get("body", "")):
                        continue
                    _file(assessment_id, url, method, a["label"], b["label"], oid, log)
                    filed += 1
                    break                          # one confirmation per template/pair is enough
                else:
                    continue
                break
    if filed:
        log(f"bola: {filed} broken object-level authorization finding(s)")
    return filed
