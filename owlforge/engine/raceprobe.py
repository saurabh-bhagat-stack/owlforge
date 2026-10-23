"""Race-condition probe (TOCTOU / missing concurrency control) — conservative, candidate-only.

Generic race detection can't be soundly auto-confirmed from outside (owlforge can't know a
resource's intended single-use semantics), so it does NOT manufacture validated findings.
For narrow single-use actions (redeem a code, withdraw, transfer, vote, claim, checkout) it
does something with a real signal:

  1. fire a small burst of identical requests CONCURRENTLY and count how many are accepted;
  2. then send one more request SEQUENTIALLY.

If the trailing sequential request is now rejected (the action enforces a single-use limit)
yet the concurrent burst slipped 2+ through, the limit was bypassed under concurrency — a
classic TOCTOU. It is filed as a candidate (the business impact depends on the resource) for
a human to confirm against the effect (balance, stock, coupon count).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from owlforge.engine.appmodel import TRANSITION, AppModel

_ONCE_VERBS = ("redeem", "claim", "apply-coupon", "applycoupon", "withdraw", "transfer",
               "vote", "refund", "cashout", "cash-out", "payout", "checkout", "purchase",
               "award", "enroll", "reserve", "book", "upvote")
_LIMIT_KW = ("rate limit", "too many", "duplicate", "already", "limit reached", "not allowed",
             "invalid", "forbidden", "conflict", "locked", "expired", "used")


def _one(sandbox, method, url, headers):
    try:
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            h = dict(headers or {})
            h["Content-Type"] = "application/x-www-form-urlencoded"
            return sandbox.http_request(method, url, headers=h, body="",
                                        follow_redirects=False) or {}
        return sandbox.http_request("GET", url, headers=headers or {},
                                    follow_redirects=False) or {}
    except Exception:
        return {}


def _accepted(resp: dict) -> bool:
    st = int(resp.get("status") or 0)
    if st in (401, 403, 409, 429) or st == 0:
        return False
    if any(k in (resp.get("body", "") or "").lower() for k in _LIMIT_KW):
        return False
    return st in (200, 201, 301, 302, 303)


def _file(assessment_id, url, method, burst, ok):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id,
            title="Possible race condition (TOCTOU): single-use action bypassed under concurrency",
            severity="high", status="candidate", confidence="low",
            endpoint=url, method=method,
            technical_analysis=(
                f"{method} {url} looks like a single-use action. owlforge sent {burst} identical "
                f"requests concurrently and {ok} were accepted, yet a following sequential request "
                "was rejected (the single-use limit IS enforced normally). That gap means the "
                "limit can be bypassed by racing requests — a check-then-act (TOCTOU) flaw with no "
                "atomic guard. Confirm the effect on the underlying resource (balance, stock, "
                "coupon count) to rate severity."),
            proof_of_concept=(f"{burst}x concurrent {method} {url} -> {ok} accepted; "
                              "a later sequential request is rejected"),
            impact="Double-spend / over-redemption: a user may redeem a one-time code multiple "
                   "times, withdraw/transfer more than allowed, or vote/claim repeatedly.",
            remediation="Make the check-and-update atomic (DB transaction with the right isolation "
                        "or a unique constraint / SELECT … FOR UPDATE / optimistic locking); do not "
                        "rely on a read-then-write without a lock.",
            validation_note="concurrent burst beat an otherwise-enforced single-use limit — verify the effect"))
        s.commit()


def race_scan(assessment_id, model: AppModel, sandbox, session_headers,
              log: Callable[[str], None] = lambda m: None, burst: int = 8, cap: int = 4) -> int:
    """Burst-test single-use transition actions for a concurrency bypass. Candidate-only."""
    if sandbox is None or not session_headers:
        return 0
    seen, filed, tested = set(), 0, 0
    for a in model.actions_of(TRANSITION):
        low = a.url.lower()
        if not a.url or a.url in seen or not any(v in low for v in _ONCE_VERBS):
            continue
        seen.add(a.url)
        method = a.method if a.method in ("POST", "PUT", "PATCH", "DELETE") else "POST"
        with ThreadPoolExecutor(max_workers=burst) as ex:
            results = list(ex.map(
                lambda _i, _m=method, _u=a.url, _h=session_headers: _one(sandbox, _m, _u, _h),
                range(burst)))
        ok = sum(1 for r in results if _accepted(r))
        trailing = _one(sandbox, method, a.url, session_headers)
        tested += 1
        if ok >= 2 and not _accepted(trailing):
            _file(assessment_id, a.url, method, burst, ok)
            log(f"scenario: race — {ok}/{burst} concurrent '{method} {a.url}' slipped the single-use limit")
            filed += 1
        if tested >= cap:
            break
    if filed:
        log(f"scenario: {filed} race-condition candidate(s)")
    return filed
