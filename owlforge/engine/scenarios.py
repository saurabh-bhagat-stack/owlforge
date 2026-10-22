"""Scenario engine — the reasoning layer that turns the app model (appmodel.py) into
business-logic and authorization hypotheses and acts on the ones that are soundly
confirmable, the way a human tester works through an application rather than a parameter
list.

Deterministic, validated-only probes (self-contained proof):
* mass_assignment_scan — submit a create/edit carrying a privileged attribute the form
  never exposed (role=admin, is_admin, balance=<marker>) and prove persistence with a
  control-vs-test differential on a FRESH read. Privilege binding -> validated; a
  client-settable ownership field (owner_id/author_id) -> candidate (needs a real victim id).
* register_privilege_scan — register a CONTROL account and a TEST account (the test one
  carrying privileged extras), then compare what each account's own session sees on the
  profile/account pages. A privileged attribute present for the test account but not the
  control account = privilege escalation at sign-up. Validated.
* unauth_action_scan — a privileged state-changing action (approve/publish/promote/…)
  that succeeds BOTH authenticated and with no session at all is reachable without
  authentication. Candidate (it could be intentionally public — a human decides).

Adaptive (LLM) half:
* run_business_logic_specialist — hands a focused, model-aware brief to an LLM specialist
  for workflow bypass, self-approval, cross-role actions and price/coupon tampering —
  intent-dependent classes owlforge will not auto-"validate" — to file evidence-backed
  candidates. Runs only when the model is worth it and a client is present.

Safe: every write targets owlforge's own seeded objects or throwaway accounts, with benign
marker data.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import urlencode, urljoin

from owlforge.engine.appmodel import CREATE, EDIT, TRANSITION, AppModel
from owlforge.engine.seed import _fill, _form_fields, _id_in_body, _looks_like_object, _session_cookie

# privileged attributes a form should never let a normal user set
_PRIV_FLAGS = (
    ("role", "admin"), ("is_admin", "true"), ("isAdmin", "true"), ("admin", "true"),
    ("is_staff", "true"), ("is_superuser", "true"), ("superuser", "true"),
    ("user_type", "admin"), ("usertype", "admin"), ("account_type", "admin"),
    ("is_verified", "true"), ("verified", "true"), ("approved", "true"),
    ("status", "approved"), ("active", "true"), ("is_active", "true"),
)
_PRIV_NUM_NAMES = ("balance", "credit", "points", "wallet", "tokens", "coins")
# fields that assign WHO owns an object — client control over these is ownership tampering
_OWNER_FIELDS = ("owner_id", "user_id", "userid", "author_id", "account_id", "created_by",
                 "owner", "author", "uid", "member_id")
# strong privileged verbs that are rarely legitimately anonymous
_STRONG_TRANSITION = ("approve", "publish", "promote", "activate", "escalate", "settle",
                      "refund", "deactivate", "disable", "/delete", "grant", "/admin")


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


def _loc(resp: dict) -> str:
    hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    return hdrs.get("location", "") or ""


def _created_url(resp: dict, base: str) -> str | None:
    loc = _loc(resp)
    if loc:
        u = urljoin(base, loc)
        if _looks_like_object(u) or u.rstrip("/") != base.rstrip("/"):
            return u
    return _id_in_body(resp.get("body", "") or "", base)


def _fill_visible(fields: dict, marker: str) -> dict:
    return {name: (fields[name] or _fill(name, marker)) for name in fields}


def _near(blob: str, name: str, val: str, window: int = 72) -> bool:
    low = blob.lower()
    nl, vl = name.lower(), val.lower()
    start = 0
    while True:
        i = low.find(vl, start)
        if i < 0:
            return False
        if low.rfind(nl, max(0, i - window), i) >= 0:
            return True
        start = i + 1


def _reflects(blob: str, name: str, val: str) -> bool:
    if not blob:
        return False
    pat = re.compile(re.escape(name) + r'["\']?\s*[:=>]\s*["\']?\s*' + re.escape(val), re.I)
    return bool(pat.search(blob)) or _near(blob, name, val)


def _num_marker() -> str:
    return str(7_000_000 + secrets.randbelow(900_000))


def _priv_extras(num: str) -> list[tuple[str, str, str]]:
    """(category, name, value) extras: privileged flags + numeric balances."""
    out = [("privilege", n, v) for n, v in _PRIV_FLAGS]
    out += [("privilege", n, num) for n in _PRIV_NUM_NAMES]
    return out


def _owner_extras(sentinel: str) -> list[tuple[str, str, str]]:
    return [("ownership", n, sentinel) for n in _OWNER_FIELDS]


# ---- mass assignment on create / edit ---------------------------------------------------
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
                        "parameters / DTOs); never mass-assign the raw request body.",
            validation_note="confirmed by control-vs-test differential on a fresh read (deterministic)"))
        s.commit()


def _file_ownership(assessment_id, url, method, field_name, sentinel):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Client-controlled object ownership via '{field_name}'",
            severity="high", status="candidate", confidence="medium",
            endpoint=url, method=method,
            technical_analysis=(
                f"On create at {method} {url}, owlforge supplied '{field_name}={sentinel}' — an "
                "owner/author identifier the form does not expose — and a fresh read of the new "
                f"object returned that value as its owner (a control object did not). If "
                f"{sentinel} maps to another user, an attacker can create objects owned by, or "
                "attributed to, someone else. Confirm against a real second account to rate it."),
            proof_of_concept=(f"create with extra {field_name}={sentinel} -> stored object's owner "
                              f"is {sentinel}"),
            impact="Objects can be created on behalf of other users (attribution/ownership "
                   "spoofing), enabling impersonation, framing or access-control confusion.",
            remediation="Derive ownership server-side from the authenticated session; never accept "
                        "an owner/author id from the request body.",
            validation_note="client-set ownership persisted (differential) — verify the id is a real user"))
        s.commit()


def _mass_assignment_hits(sandbox, url, method, session_headers) -> list[tuple[str, str, str]]:
    """Return [(category, name, value)] for extra fields that persist on a fresh read but do
    not appear on a control object. category is 'privilege' or 'ownership'."""
    html = _get(sandbox, url, session_headers).get("body", "") or ""
    fields = _form_fields(html, url)
    if not fields:
        return []
    low = url.lower()
    is_edit = method in ("PUT", "PATCH") or any(
        k in low for k in ("edit", "update", "profile", "settings", "account"))
    extras = _priv_extras(_num_marker()) + _owner_extras("9" + str(secrets.randbelow(900_000) + 100_000))

    if is_edit:
        base_blob = html
        body = _fill_visible(fields, "owl" + secrets.token_hex(3))
        for _c, n, v in extras:
            body.setdefault(n, v)
        resp = _post(sandbox, url, urlencode(body), session_headers)
        if not _ok(resp):
            return []
        test_blob = _get(sandbox, url, session_headers).get("body", "") or resp.get("body", "") or ""
        return [(c, n, v) for c, n, v in extras
                if _reflects(test_blob, n, v) and not _reflects(base_blob, n, v)]

    # CREATE: control object (no extras) vs test object (with extras), both fresh-read
    cresp = _post(sandbox, url, urlencode(_fill_visible(fields, "owl" + secrets.token_hex(3))), session_headers)
    if not _ok(cresp):
        return []
    curl = _created_url(cresp, url)
    cblob = (_get(sandbox, curl, session_headers).get("body", "") if curl else "") or cresp.get("body", "") or ""

    tbody = _fill_visible(fields, "owl" + secrets.token_hex(3))
    for _c, n, v in extras:
        tbody.setdefault(n, v)
    tresp = _post(sandbox, url, urlencode(tbody), session_headers)
    if not _ok(tresp):
        return []
    turl = _created_url(tresp, url)
    if not turl:                       # require a fresh read of the stored object (no echo FPs)
        return []
    tblob = _get(sandbox, turl, session_headers).get("body", "") or ""
    return [(c, n, v) for c, n, v in extras
            if _reflects(tblob, n, v) and not _reflects(cblob, n, v)]


def mass_assignment_scan(assessment_id, model: AppModel, sandbox, session_headers,
                         log: Callable[[str], None] = lambda m: None, cap: int = 6) -> int:
    """Test create/edit actions for mass-assignment: privileged-field binding (validated)
    and client-controlled ownership (candidate)."""
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
        hits = _mass_assignment_hits(sandbox, a.url, a.method, session_headers)
        priv = next((h for h in hits if h[0] == "privilege"), None)
        own = next((h for h in hits if h[0] == "ownership"), None)
        if priv:
            _file_mass_assignment(assessment_id, a.url, a.method, priv[1], priv[2])
            log(f"scenario: mass assignment — '{priv[1]}' bound on {a.method} {a.url}")
            filed += 1
        if own:
            _file_ownership(assessment_id, a.url, a.method, own[1], own[2])
            log(f"scenario: client-controlled ownership — '{own[1]}' on {a.method} {a.url}")
            filed += 1
        if tested >= cap:
            break
    if filed:
        log(f"scenario: {filed} mass-assignment finding(s) on {tested} create/edit action(s)")
    elif tested:
        log(f"scenario: create/edit actions reject unknown fields on {tested} action(s)")
    return filed


# ---- privilege escalation at registration -----------------------------------------------
_REG_HINT = ("register", "signup", "sign-up", "sign_up", "/join", "create-account",
             "createaccount", "users/new", "accounts/new", "registration")
_PROFILE_HINT = ("/me", "profile", "account", "dashboard", "/user", "settings", "/home", "whoami")


def _register(sandbox, url, extra_params, extras) -> dict | None:
    """Register one marker account (optionally with privileged extras). Returns
    {headers, loc} when a session starts, else None."""
    html = _get(sandbox, url, None).get("body", "") or ""
    fields = _form_fields(html, url)
    for p in extra_params or []:
        fields.setdefault(p, "")
    if not any(any(x in n.lower() for x in ("password", "passwd", "pwd", "pass")) for n in fields):
        return None
    marker = "owl" + secrets.token_hex(4)
    for n in list(fields):
        fields[n] = _fill(n, marker)
    for _c, n, v in extras:
        fields.setdefault(n, v)
    resp = _post(sandbox, url, urlencode(fields), None)
    if not _ok(resp):
        return None
    headers = _session_cookie(resp)
    return {"headers": headers, "loc": _loc(resp)} if headers else None


def _profile_urls(inventory, target, extra_loc="") -> list[str]:
    urls, seen = [], set()

    def add(u):
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    if extra_loc:
        add(urljoin(target, extra_loc))
    for it in inventory or []:
        u = it.get("url") or ""
        if u and (it.get("method") or "GET").upper() == "GET" and any(h in u.lower() for h in _PROFILE_HINT):
            add(u)
    for p in ("/me", "/profile", "/account", "/dashboard", "/api/me", "/user", "/home", "/settings"):
        add(urljoin(target, p))
    return urls[:10]


def _file_register_priv(assessment_id, url, field_name, field_val):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Privilege escalation at registration via '{field_name}'",
            severity="critical", status="validated", confidence="high",
            endpoint=url, method="POST",
            technical_analysis=(
                f"The sign-up endpoint {url} bound the extra attribute '{field_name}={field_val}'. "
                "owlforge registered a CONTROL account (plain fields) and a TEST account (same "
                f"fields plus {field_name}={field_val}); each account's own session was then read "
                f"on the profile/account pages. The test account shows {field_name}={field_val} "
                "and the control account does not, so anyone who can register can grant themselves "
                "that privileged attribute at account creation."),
            proof_of_concept=(f"POST sign-up with extra {field_name}={field_val} -> the new "
                              f"account's profile shows {field_name}={field_val} (a control "
                              "registration without it does not)"),
            impact="Anonymous privilege escalation: an attacker self-registers directly into an "
                   "admin/privileged/verified role without any existing access.",
            remediation="Never mass-assign the registration body; set role/verification/flags "
                        "server-side to safe defaults and change them only through authorized flows.",
            validation_note="control-vs-test registration differential across two sessions (deterministic)"))
        s.commit()


def register_privilege_scan(assessment_id, inventory, sandbox, target,
                            log: Callable[[str], None] = lambda m: None) -> int:
    """Register control + test accounts and detect privileged fields bound at sign-up."""
    if sandbox is None:
        return 0
    reg = None
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST":
            continue
        url = (it.get("url") or "")
        params = [p.lower() for p in (it.get("params") or [])]
        has_pass = any(any(x in p for x in ("password", "passwd", "pwd", "pass")) for p in params)
        if any(h in url.lower() for h in _REG_HINT) or (
                has_pass and any("confirm" in p or "repeat" in p for p in params)):
            reg = it
            break
    if not reg:
        return 0
    url = reg["url"]
    control = _register(sandbox, url, reg.get("params"), [])
    if not control or not control["headers"]:
        log("scenario: registration gives no auto-session — skipping sign-up privilege check")
        return 0
    num = _num_marker()
    test = _register(sandbox, url, reg.get("params"), _priv_extras(num))
    if not test or not test["headers"]:
        return 0
    profiles = _profile_urls(inventory, target, control.get("loc") or test.get("loc"))
    cblob = "\n".join(_get(sandbox, u, control["headers"]).get("body", "") or "" for u in profiles)
    tblob = "\n".join(_get(sandbox, u, test["headers"]).get("body", "") or "" for u in profiles)
    for _c, n, v in _priv_extras(num):
        if _reflects(tblob, n, v) and not _reflects(cblob, n, v):
            _file_register_priv(assessment_id, url, n, v)
            log(f"scenario: privilege escalation at registration — '{n}={v}'")
            return 1
    log("scenario: registration does not bind privileged fields (checked)")
    return 0


# ---- unauthenticated access to privileged state-changing actions ------------------------
_LOGIN_REDIR = ("login", "signin", "sign-in", "sign_in", "/auth")


def _reachable(resp: dict) -> bool:
    if not resp or int(resp.get("status") or 0) in (401, 403):
        return False
    if int(resp.get("status") or 0) in (301, 302, 303):
        return not any(h in _loc(resp).lower() for h in _LOGIN_REDIR)
    return int(resp.get("status") or 0) in (200, 201)


def _file_unauth_action(assessment_id, url, method):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Privileged state-changing action reachable without authentication",
            severity="high", status="candidate", confidence="medium",
            endpoint=url, method=method,
            technical_analysis=(
                f"{method} {url} looks like a privileged state transition (approve/publish/"
                "promote/activate/delete/…), yet it returned a success response with NO session "
                "attached — the same as with a valid session. If this action is meant to be "
                "restricted, it is missing an authentication/authorization check. Confirm the "
                "action's intended audience before rating."),
            proof_of_concept=f"{method} {url} with no cookies -> success (not 401/403/login-redirect)",
            impact="Unauthenticated users may trigger privileged workflow transitions (approve, "
                   "publish, promote, delete), bypassing the application's access model.",
            remediation="Require authentication and a server-side role/ownership check on every "
                        "state-changing endpoint; deny by default.",
            validation_note="reachable anonymously (success, not login-gated) — verify it should be restricted"))
        s.commit()


def unauth_action_scan(assessment_id, model: AppModel, sandbox, session_headers,
                       log: Callable[[str], None] = lambda m: None, cap: int = 8) -> int:
    """Privileged transition actions that succeed with no session at all -> candidate."""
    if sandbox is None:
        return 0
    seen, filed, tested = set(), 0, 0
    for a in model.actions_of(TRANSITION):
        low = a.url.lower()
        if not a.url or a.url in seen or not any(v in low for v in _STRONG_TRANSITION):
            continue
        seen.add(a.url)
        method = a.method if a.method in ("POST", "PUT", "DELETE", "PATCH") else "POST"
        anon = _post(sandbox, a.url, "", {}) if method == "POST" else None
        if anon is None:
            try:
                anon = sandbox.http_request(method, a.url, headers={}, body=None,
                                            follow_redirects=False) or {}
            except Exception:
                anon = {}
        if not _reachable(anon):
            continue
        # it must also work authenticated (otherwise it is just a public page, not a bypass)
        if session_headers:
            authed = _post(sandbox, a.url, "", session_headers) if method == "POST" else \
                _get(sandbox, a.url, session_headers)
            if not _reachable(authed):
                continue
        tested += 1
        _file_unauth_action(assessment_id, a.url, method)
        log(f"scenario: {method} {a.url} reachable without authentication (candidate)")
        filed += 1
        if tested >= cap:
            break
    return filed


# ---- the adaptive (LLM) half ------------------------------------------------------------
def business_logic_brief(model: AppModel) -> str:
    """A focused, model-aware brief for the business-logic specialist."""
    multi = len([r for r in model.roles if r.headers]) >= 2
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
        hyps.append("WORKFLOW/STEP BYPASS: invoke a later-stage action directly (checkout/"
                    "confirm/approve/publish) without completing its prerequisites, or out of "
                    "order. Success without the prior step = a bypass.")
        hyps.append("SELF-APPROVAL: as the actor who created an item, perform an action that "
                    "should need a different/higher role (approve/publish/verify your own).")
    if multi or priv:
        hyps.append("CROSS-ROLE ACTION: take an action available to a privileged role and "
                    "replay it as a lower-privilege session; if it still succeeds, function-level "
                    "authorization is missing.")
    hyps.append("PRICE/QUANTITY TAMPERING: on any order/payment/cart flow, change price, total, "
                "quantity, discount or currency and see if the server trusts it (incl. negative/zero).")
    hyps.append("COUPON/VOUCHER ABUSE: apply a single-use code twice, or stack codes, and check "
                "the discount is granted more than once.")
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
