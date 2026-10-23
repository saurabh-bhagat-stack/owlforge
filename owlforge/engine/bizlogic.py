"""Business-logic probes — deliberately conservative.

Generic business-logic abuse (price/quantity tampering, workflow bypass, race conditions)
is app-specific and NOT soundly auto-confirmable, so owlforge does NOT manufacture
"validated" findings here. It runs one narrow, bounded probe — does a money/quantity
parameter accept a negative value without rejection? — and files a clearly-labelled
CANDIDATE for manual verification. Low noise, honest: a human decides if it matters.
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import Callable

_MONEY = ("price", "amount", "qty", "quantity", "total", "cost", "balance", "discount",
          "credit", "points", "value", "count", "stock", "fee", "unit", "subtotal", "refund")
_SUSPECT = ("-1", "0", "0.01")  # negative / free / underpay
_ERROR_KW = ("invalid", "must be", "not allowed", "error", "cannot be negative",
             "greater than", "positive", "out of range", "bad request")


def _is_money(name: str) -> bool:
    n = (name or "").lower()
    return any(n == k or n.endswith(k) or k in n for k in _MONEY)


def _targets(inventory):
    seen, out = set(), []
    for it in inventory:
        for p in (it.get("params") or []):
            if _is_money(p):
                key = (it["url"], p)
                if key not in seen:
                    seen.add(key)
                    out.append({"url": it["url"], "param": p,
                                "method": (it.get("method") or "GET").upper()})
    return out


def _file_candidate(assessment_id, url, method, param, accepted, note):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    vals = ", ".join(accepted)
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Possible business-logic flaw: unchecked numeric value accepted for '{param}'",
            severity="medium", status="candidate", confidence="low",
            endpoint=url, method=method,
            technical_analysis=note,
            proof_of_concept=f"{param} = {vals} accepted (HTTP 200, reflected, no validation error)",
            impact="If the value drives pricing, balances or quantities, an attacker-chosen "
                   "value (negative, zero or fractional) may be exploitable (e.g. free/underpaid "
                   "order, credit instead of charge) — verify the effect.",
            remediation="Validate numeric inputs server-side (allowed range, sign, precision) and "
                        "re-check invariants (totals, balances) before committing.",
            validation_note="possible business-logic issue — needs manual verification"))
        s.commit()


def bizlogic_scan(assessment_id, inventory, sandbox, session_headers,
                  log: Callable[[str], None] = lambda m: None) -> int:
    if sandbox is None:
        return 0
    from owlforge.engine.preprobe import _send

    targets = _targets(inventory)
    if not targets:
        return 0
    log(f"business-logic: testing {min(len(targets), 15)} money/quantity param(s) "
        "for unchecked numeric values (negative/zero/fractional; candidates only)")
    filed = 0
    for t in targets[:15]:
        base = _send(sandbox, t["method"], t["url"], t["param"], "1", session_headers) or {}
        if int(base.get("status") or 0) != 200:
            continue
        accepted = []
        for val in _SUSPECT:
            r = _send(sandbox, t["method"], t["url"], t["param"], val, session_headers) or {}
            body = r.get("body") or ""
            if int(r.get("status") or 0) == 200 and val in body \
                    and not any(k in body.lower() for k in _ERROR_KW):
                accepted.append(val)
        if accepted:
            _file_candidate(
                assessment_id, t["url"], t["method"], t["param"], accepted,
                f"{t['method']} {t['url']} accepted {t['param']} = {', '.join(accepted)} with "
                "HTTP 200 and no validation error (the value is reflected). If this parameter "
                "affects price/quantity/balance, it may be tamperable.")
            filed += 1
    if filed:
        log(f"business-logic: {filed} candidate(s) flagged for manual review")
    return filed


_COUPON_HINTS = ("coupon", "promo", "voucher", "discount_code", "discountcode", "giftcard",
                 "gift_card", "promocode", "promo_code", "referral_code", "discount")
_APPLIED_KW = ("discount applied", "coupon applied", "promo applied", "% off", "you saved",
               "amount saved", "deducted", "discount of", "applied successfully", "voucher applied")
_REJECT_KW = ("invalid", "unknown", "expired", "not found", "does not exist", "already used",
              "not valid", "no such", "incorrect", "cannot be applied")


def _coupon_params(inventory):
    seen, out = set(), []
    for it in inventory or []:
        if (it.get("method") or "GET").upper() not in ("POST", "PUT", "PATCH"):
            continue
        for p in (it.get("params") or []):
            if any(h in p.lower() for h in _COUPON_HINTS):
                key = (it["url"], p)
                if key not in seen:
                    seen.add(key)
                    out.append({"url": it["url"], "param": p,
                                "method": (it.get("method") or "POST").upper()})
    return out


def _file_coupon(assessment_id, url, method, param, reusable):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    extra = (" The same code was then accepted a SECOND time with no 'already used' response, "
             "so it also looks reusable.") if reusable else ""
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=f"Weak coupon/discount validation on '{param}'",
            severity="medium", status="candidate", confidence="low",
            endpoint=url, method=method,
            technical_analysis=(
                f"{method} {url} applied a discount for an ARBITRARY, owlforge-invented code via "
                f"'{param}' (the response reported the discount as applied, with no rejection)."
                + extra + " Verify the code's validity and single-use enforcement against a real "
                "order total."),
            proof_of_concept=f"{param} = OWLSAVE50 -> response reports a discount applied",
            impact="An attacker may obtain unauthorized discounts, or reuse a single-use code, "
                   "if codes are not validated and consumed server-side.",
            remediation="Validate coupon codes against stored, unredeemed records and atomically "
                        "mark them consumed; never apply a discount for an unknown code.",
            validation_note="arbitrary coupon code accepted — verify validity/single-use (candidate)"))
        s.commit()


def coupon_scan(assessment_id, inventory, sandbox, session_headers,
                log=lambda m: None) -> int:
    """Deterministic, candidate-only: does a coupon/discount field accept an ARBITRARY code
    (weak validation), and is the same code accepted twice (possible reuse)?"""
    if sandbox is None:
        return 0
    from owlforge.engine.preprobe import _send
    targets = _coupon_params(inventory)
    if not targets:
        return 0
    filed = 0
    for t in targets[:10]:
        r1 = _send(sandbox, t["method"], t["url"], t["param"], "OWLSAVE50", session_headers) or {}
        b1 = (r1.get("body") or "").lower()
        if int(r1.get("status") or 0) not in (200, 201, 302, 303):
            continue
        if any(k in b1 for k in _APPLIED_KW) and not any(k in b1 for k in _REJECT_KW):
            r2 = _send(sandbox, t["method"], t["url"], t["param"], "OWLSAVE50", session_headers) or {}
            b2 = (r2.get("body") or "").lower()
            reusable = any(k in b2 for k in _APPLIED_KW) and not any(k in b2 for k in _REJECT_KW)
            _file_coupon(assessment_id, t["url"], t["method"], t["param"], reusable)
            filed += 1
    if filed:
        log(f"business-logic: {filed} weak-coupon candidate(s)")
    return filed
