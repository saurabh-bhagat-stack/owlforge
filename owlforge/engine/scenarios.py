"""Scenario engine — the reasoning layer that turns the app model (appmodel.py) into
business-logic and authorization hypotheses and acts on the ones that are soundly
confirmable, the way a human tester works through an application rather than a parameter
list.

Two halves, matching owlforge's split-brain design:

* mass_assignment_scan — DETERMINISTIC and validated-only. Mass assignment / privilege
  escalation is one business-logic class that IS soundly provable: submit a create/edit
  with a privileged attribute the form never exposed (role=admin, is_admin=true,
  balance=<marker>), then re-read the stored object. If the injected attribute comes back
  persisted on a fresh read — and a control object created WITHOUT it does not carry it —
  the server bound an unauthorized field. That differential is self-contained proof, so it
  is filed validated. No persistence confirmed -> nothing filed (honest, low-noise).

* run_business_logic_specialist — the ADAPTIVE half. Workflow bypass, approve-your-own,
  price/coupon tampering and step-skipping depend on intended policy that can't be known
  from the outside, so owlforge does NOT manufacture "validated" findings for them. Instead
  it hands a focused, model-aware brief to an LLM specialist that explores and files
  evidence-backed candidates for a human to judge. It only runs when a model is worth it.

Safe: every write targets owlforge's own seeded objects or a throwaway account, with
benign marker data.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import urlencode, urljoin

from owlforge.engine.appmodel import CREATE, EDIT, AppModel
from owlforge.engine.seed import _fill, _form_fields, _id_in_body, _looks_like_object

# privileged attributes a form should never let a normal user set
_PRIV_FLAGS = (
    ("role", "admin"), ("is_admin", "true"), ("isAdmin", "true"), ("admin", "true"),
    ("is_staff", "true"), ("is_superuser", "true"), ("superuser", "true"),
    ("user_type", "admin"), ("usertype", "admin"), ("account_type", "admin"),
    ("is_verified", "true"), ("verified", "true"), ("approved", "true"),
    ("status", "approved"), ("active", "true"), ("is_active", "true"),
)
_PRIV_NUM_NAMES = ("balance", "credit", "points", "wallet", "tokens", "coins")


def _get(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}) or {}
    except Exception:
        return {}


def _post(sandbox, url, body, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return sandbox.http_request("POST", url, headers=h, body=body, follow_redirects=False) or {}
    except Exception:
        return {}


def _ok(resp: dict) -> bool:
    return int(resp.get("status") or 0) in (200, 201, 301, 302, 303)


def _created_url(resp: dict, base: str) -> str | None:
    hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    loc = hdrs.get("location", "")
    if loc:
        u = urljoin(base, loc)
        if _looks_like_object(u) or u.rstrip("/") != base.rstrip("/"):
            return u
    return _id_in_body(resp.get("body", "") or "", base)


def _fill_visible(fields: dict, marker: str) -> dict:
    out = {}
    for name in fields:
        out[name] = fields[name] or _fill(name, marker)
    return out


def _near(blob: str, name: str, val: str, window: int = 72) -> bool:
    """True if `name` appears shortly before `val` — i.e. the object representation carries
    `name: val` / `"name":"val"` / a name cell next to a val cell. Robust for JSON and HTML."""
    low = blob.lower()
    nl, vl = name.lower(), val.lower()
    start = 0
    while True:
        i = low.find(vl, start)
        if i < 0:
            return False
        j = low.rfind(nl, max(0, i - window), i)
        if j >= 0:
            return True
        start = i + 1


def _reflects(blob: str, name: str, val: str) -> bool:
    if not blob:
        return False
    pat = re.compile(re.escape(name) + r'["\']?\s*[:=>]\s*["\']?\s*' + re.escape(val), re.I)
    return bool(pat.search(blob)) or _near(blob, name, val)


def _priv_payload(marker: str) -> list[tuple[str, str]]:
    extras = list(_PRIV_FLAGS)
    num = str(7_000_000 + secrets.randbelow(900_000))  # unique-ish 7-digit marker
    for n in _PRIV_NUM_NAMES:
        extras.append((n, num))
    return extras


def _file_mass_assignment(assessment_id, url, method, field_name, field_val):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Mass assignment / privilege escalation via '{field_name}'",
            severity="high", status="validated", confidence="high",
            endpoint=url, method=method,
            technical_analysis=(
                f"A create/update at {method} {url} bound the attribute '{field_name}', which "
                f"the form never exposed. owlforge submitted '{field_name}={field_val}' as an "
                "extra field and a FRESH read of the stored object returned it as persisted, "
                "while a control object created WITHOUT that field did not carry it. The server "
                "mass-assigns request parameters onto the model, so a user can set privileged "
                "attributes (role/verification/balance) they must not control."),
            proof_of_concept=(f"submit the normal form plus extra field {field_name}={field_val} "
                              f"-> re-read the object shows {field_name}={field_val} (control "
                              "object without it does not)"),
            impact="Privilege escalation or integrity break: a normal user can grant themselves "
                   "a role, mark themselves verified/approved, or set balances/points directly.",
            remediation="Bind only an explicit allow-list of fields to the model (strong "
                        "parameters / DTOs); never mass-assign the raw request body. Set "
                        "role/verification/balance only through authorized server-side paths.",
            validation_note="confirmed by control-vs-test differential on a fresh read (deterministic)"))
        s.commit()


def _try_mass_assignment(sandbox, url, method, session_headers) -> tuple[str, str] | None:
    """Return (field, value) if a privileged extra field persists on a fresh read; else None."""
    html = _get(sandbox, url, session_headers).get("body", "") or ""
    fields = _form_fields(html, url)
    if not fields:
        return None
    is_edit = method in ("PUT", "PATCH") or "edit" in url.lower() or "update" in url.lower() \
        or "profile" in url.lower() or "settings" in url.lower() or "account" in url.lower()

    if is_edit:
        # baseline = the object as it is now; test = after an edit carrying privileged extras
        base_blob = html
        marker = "owl" + secrets.token_hex(3)
        body = _fill_visible(fields, marker)
        extras = _priv_payload(marker)
        for n, v in extras:
            body.setdefault(n, v)
        resp = _post(sandbox, url, urlencode(body), session_headers)
        if not _ok(resp):
            return None
        test_blob = _get(sandbox, url, session_headers).get("body", "") or resp.get("body", "") or ""
        for n, v in extras:
            if _reflects(test_blob, n, v) and not _reflects(base_blob, n, v):
                return (n, v)
        return None

    # CREATE: a control object (no extras) vs a test object (with extras), both fresh-read
    cmk = "owl" + secrets.token_hex(3)
    cresp = _post(sandbox, url, urlencode(_fill_visible(fields, cmk)), session_headers)
    if not _ok(cresp):
        return None
    curl = _created_url(cresp, url)
    cblob = (_get(sandbox, curl, session_headers).get("body", "") if curl else "") or cresp.get("body", "") or ""

    tmk = "owl" + secrets.token_hex(3)
    tbody = _fill_visible(fields, tmk)
    extras = _priv_payload(tmk)
    for n, v in extras:
        tbody.setdefault(n, v)
    tresp = _post(sandbox, url, urlencode(tbody), session_headers)
    if not _ok(tresp):
        return None
    turl = _created_url(tresp, url)
    # require a FRESH read of the stored object (not just the POST echo) to avoid reflection FPs
    if not turl:
        return None
    tblob = _get(sandbox, turl, session_headers).get("body", "") or ""
    for n, v in extras:
        if _reflects(tblob, n, v) and not _reflects(cblob, n, v):
            return (n, v)
    return None


def mass_assignment_scan(assessment_id, model: AppModel, sandbox, session_headers,
                         log: Callable[[str], None] = lambda m: None, cap: int = 6) -> int:
    """Test create/edit actions in the model for mass-assignment privilege escalation.
    Validated-only: files a finding only when a privileged extra field is proven persisted."""
    if sandbox is None or not session_headers:
        return 0
    seen, filed, tested = set(), 0, 0
    for a in model.actions_of(CREATE, EDIT):
        if not a.url or a.url in seen:
            continue
        low = a.url.lower()
        if any(h in low for h in ("login", "logout", "register", "signup")):
            continue
        seen.add(a.url)
        tested += 1
        hit = _try_mass_assignment(sandbox, a.url, a.method, session_headers)
        if hit:
            _file_mass_assignment(assessment_id, a.url, a.method, hit[0], hit[1])
            log(f"scenario: mass assignment — '{hit[0]}' bound on {a.method} {a.url}")
            filed += 1
        if tested >= cap:
            break
    if filed:
        log(f"scenario: {filed} mass-assignment finding(s) on {tested} create/edit action(s)")
    elif tested:
        log(f"scenario: create/edit actions reject unknown fields on {tested} action(s)")
    return filed


# ---- the adaptive (LLM) half ------------------------------------------------------------
def business_logic_brief(model: AppModel) -> str:
    """A focused, model-aware brief for the business-logic specialist. It names the concrete
    hypotheses a tester would try against THIS app's entities/roles/workflows."""
    roles = model.roles
    multi = len([r for r in roles if r.headers]) >= 2
    priv = model.privileged_roles()
    lines = [
        "You are a BUSINESS-LOGIC & AUTHORIZATION specialist. Reason about how this specific "
        "application is meant to work, then test where that intent can be subverted. Do NOT "
        "re-run generic injection fuzzing — other specialists cover that.",
        "",
        "# The application model owlforge built",
        model.summary(),
        "",
        "# Hypotheses to test (pick the ones that fit the model; stop when confirmed):",
    ]
    hyps = []
    if model.has_transitions():
        hyps.append("WORKFLOW/STEP BYPASS: invoke a later-stage action directly (e.g. a "
                    "checkout/confirm/approve/publish endpoint) without completing its "
                    "prerequisites, or out of order. Success without the prior step = a bypass.")
        hyps.append("SELF-APPROVAL: as the actor who created an item, perform an action that "
                    "should need a different/higher role (approve/publish/verify your own). If "
                    "it succeeds, authorization on the transition is missing.")
    if multi or priv:
        hyps.append("CROSS-ROLE ACTION: take an action available to a privileged role and "
                    "replay it as a lower-privilege session; if it still succeeds, function-level "
                    "authorization is missing.")
    hyps.append("PRICE/QUANTITY TAMPERING: on any order/payment/cart flow, change price, total, "
                "quantity, discount or currency client-side and see if the server trusts it "
                "(including negative or zero values).")
    hyps.append("COUPON/VOUCHER ABUSE: apply the same single-use code twice, or stack codes, and "
                "check the discount is granted more than once.")
    hyps.append("PARAMETER-DRIVEN IDENTITY: swap an owner_id / user_id / account field in a "
                "state-changing request to act on behalf of another identity.")
    for i, h in enumerate(hyps, 1):
        lines.append(f"{i}. {h}")
    lines += [
        "",
        "Use http_request against the real endpoints. The MOMENT you reproduce an issue, call "
        "create_finding with a clear proof_of_concept (the exact request and the response that "
        "proves it) and a structured repro when you can; label it a candidate if its severity "
        "depends on intended policy. Then call finish. File nothing you cannot reproduce.",
    ]
    return "\n".join(lines)


async def run_business_logic_specialist(*, client, sandbox, assessment_id, target, model: AppModel,
                                        emit, session_headers, scan_mode="deep", max_turns=10) -> int:
    """Run one model-aware LLM specialist for business-logic / workflow / authz abuse.
    Returns 1 if it ran, 0 if skipped (no client or model not worth it)."""
    if client is None or not model.is_interesting():
        return 0
    from owlforge.engine.agent import run_single_agent
    from owlforge.tools.builtin import build_registry
    registry = build_registry(with_sandbox=sandbox is not None)
    emit("status", "[specialist:business-logic] reasoning over the app model "
         f"({len(model.entities)} entit(y/ies), {len(model.workflows)} workflow(s))")
    try:
        await run_single_agent(
            client=client, registry=registry, emit=emit, assessment_id=assessment_id,
            target=target, instructions=business_logic_brief(model), scan_mode=scan_mode,
            max_turns=max_turns, sandbox=sandbox, session_headers=session_headers,
            surface=model.summary(),
        )
    except Exception as e:
        emit("error", f"business-logic specialist crashed: {type(e).__name__}: {e}")
    return 1
