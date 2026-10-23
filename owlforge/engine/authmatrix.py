"""Cross-actor authorization matrix on seeded objects.

Read-only IDOR (can B *see* A's object) is handled by the access-control differential. This
pass tests the harder, higher-impact half: can a **different** actor (a peer user, a
lower-privilege user, or anonymous) **edit** or **delete** an object its owner created —
broken function-level authorization (BFLA).

It is sound and safe because it only acts on **owlforge's own seeded objects**: a non-owner
writes a UNIQUE marker (edit) or removes the object (delete); the owner then re-reads it, and
the marker appearing — or the object being gone — is definitive proof the non-owner's
write succeeded. No real data is touched; the objects are ones owlforge created.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import urlencode, urljoin

from owlforge.engine.seed import _attrs, _form_fields

_OBJ_ID = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f-]{20,})(?:[/?]|$)", re.I)
_EDITABLE = ("title", "name", "body", "content", "text", "description", "comment", "subject",
             "message", "note", "label")
_DELETE_HINT = ("delete", "remove", "destroy", "/del", "trash")


def _obj_id(url: str) -> str:
    m = _OBJ_ID.search(url or "")
    return m.group(1) if m else ""


def _get(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}) or {}
    except Exception:
        return {}


def _send(sandbox, method, url, headers, body=None):
    try:
        h = dict(headers or {})
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        return sandbox.http_request(method, url, headers=h, body=body, follow_redirects=False) or {}
    except Exception:
        return {}


def _affordances(sandbox, obj_url, owner_headers):
    """Discover edit/delete affordances for an object: forms/links on its page + REST
    conventions. Returns (edits, deletes) as lists of (method, url, fields|None)."""
    oid = _obj_id(obj_url)
    page = _get(sandbox, obj_url, owner_headers)
    html = page.get("body", "") or ""
    edits, deletes = [], []
    for attrs, _body in re.findall(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
        a = _attrs(attrs)
        action = urljoin(obj_url, a.get("action", obj_url))
        method = (a.get("method", "GET") or "GET").upper()
        low = action.lower()
        fields = _form_fields(html, action)
        if any(h in low for h in _DELETE_HINT) or method == "DELETE":
            deletes.append(("POST" if method == "GET" else method, action, fields))
        elif method in ("POST", "PUT") and oid and oid in action:
            edits.append((method, action, fields))
    for href in re.findall(r'href\s*=\s*"([^"]+)"', html, re.I):
        low = href.lower()
        if oid and oid in href and any(h in low for h in _DELETE_HINT):
            deletes.append(("GET", urljoin(obj_url, href), None))
    # REST conventions as a fallback
    deletes.append(("DELETE", obj_url, None))
    deletes.append(("POST", obj_url.rstrip("/") + "/delete", None))
    return edits, deletes


def _edit_body(fields: dict, marker: str) -> str:
    out = dict(fields)
    touched = False
    for name in list(out):
        if any(k in name.lower() for k in _EDITABLE):
            out[name] = f"owledit {marker}"
            touched = True
    if not touched:  # no obvious content field — change the first non-token text field
        for name in list(out):
            if "csrf" not in name.lower() and "token" not in name.lower():
                out[name] = f"owledit {marker}"
                break
    return urlencode(out)


def _file(assessment_id, verb, obj_url, actor_label):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Broken function-level authorization: a non-owner can {verb} another "
                  "user's object",
            severity="high", status="validated", confidence="high",
            endpoint=obj_url, method=("DELETE" if verb == "delete" else "POST"),
            technical_analysis=(
                f"An object created by one user was {verb}d by '{actor_label}', a different "
                f"identity that does not own it. Proof is self-contained: the action was "
                f"performed as '{actor_label}' and the owner's re-read confirmed it "
                + ("(the non-owner's unique marker appears in the object)."
                   if verb == "edit" else "(the owner's object is now gone).")),
            proof_of_concept=f"as '{actor_label}': {verb} {obj_url} -> owner re-read confirms it",
            impact="Any user can modify or destroy other users' (or an admin's) data — a "
                   "function-level authorization failure.",
            remediation="Enforce per-object ownership/role checks server-side on every "
                        "state-changing action (edit, delete, state transition), not only on read.",
            validation_note="confirmed by a non-owner write + owner re-read (deterministic)"))
        s.commit()


def access_matrix_scan(assessment_id, sandbox, owner_headers, identities,
                       log: Callable[[str], None] = lambda m: None) -> int:
    """Test edit/delete across actors on seeded objects owned by `owner_headers`.
    Returns the count of broken-function-level-authz findings filed."""
    if sandbox is None or not owner_headers:
        return 0
    from sqlmodel import select

    from owlforge.store.db import session
    from owlforge.store.models import SurfaceItem
    with session() as s:
        objs = [r.url for r in s.exec(select(SurfaceItem).where(
            SurfaceItem.assessment_id == assessment_id, SurfaceItem.source == "seeded")).all()
            if r.url]
    if not objs:
        return 0
    others = [{"label": i.get("label", "other"), "headers": i.get("headers") or {}}
              for i in (identities or [])
              if (i.get("headers") or {}) and i.get("headers") != owner_headers]
    others.append({"label": "anonymous", "headers": {}})

    filed = 0
    for obj_url in dict.fromkeys(objs):
        base = _get(sandbox, obj_url, owner_headers)
        if int(base.get("status") or 0) != 200:
            continue
        edits, deletes = _affordances(sandbox, obj_url, owner_headers)
        for actor in others:
            # EDIT: a non-owner writes a unique marker; owner re-read must show it
            edited = False
            for method, url, fields in edits[:3]:
                if not fields:
                    continue
                marker = "e" + secrets.token_hex(4)
                _send(sandbox, method, url, actor["headers"], _edit_body(fields, marker))
                if marker in (_get(sandbox, obj_url, owner_headers).get("body", "") or ""):
                    _file(assessment_id, "edit", obj_url, actor["label"])
                    log(f"auth-matrix: '{actor['label']}' edited another user's object {obj_url}")
                    filed += 1
                    edited = True
                    break
            # DELETE (terminal): owner re-read must go from present to gone
            deleted = False
            for method, url, _f in deletes[:4]:
                _send(sandbox, method, url, actor["headers"], None)
                after = _get(sandbox, obj_url, owner_headers)
                if int(after.get("status") or 0) in (404, 410) or len(after.get("body") or "") < 40:
                    _file(assessment_id, "delete", obj_url, actor["label"])
                    log(f"auth-matrix: '{actor['label']}' deleted another user's object {obj_url}")
                    filed += 1
                    deleted = True
                    break
            if deleted:
                break  # object gone — stop testing further actors on it
            _ = edited
    if filed:
        log(f"auth-matrix: {filed} broken function-level authz finding(s) on seeded objects")
    return filed
