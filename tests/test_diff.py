"""Cross-run diff logic."""
from __future__ import annotations

from types import SimpleNamespace as NS


def _f(title, ep, status="validated"):
    return NS(title=title, endpoint=ep, status=status)


def test_diff_new_fixed_persisting():
    from owlforge.report.diff import diff_findings
    previous = [_f("SQL injection", "/catalog"), _f("Reflected XSS", "/search"),
                _f("Missing HSTS", "/")]
    current = [_f("SQL injection", "/catalog"),            # persisting
               _f("Blind SSRF via 'storeId'", "/stock")]   # new
    # XSS + HSTS disappeared -> fixed
    d = diff_findings(current, previous)
    assert ("sql injection", "/catalog") in d["persisting"]
    assert ("blind ssrf via 'storeid'", "/stock") in d["new"]
    fixed = set(d["fixed"])
    assert ("reflected xss", "/search") in fixed and ("missing hsts", "/") in fixed
    assert len(d["new"]) == 1 and len(d["persisting"]) == 1 and len(d["fixed"]) == 2


def test_diff_ignores_non_live_status():
    from owlforge.report.diff import diff_findings
    cur = [_f("A", "/x", status="duplicate"), _f("B", "/y", status="validated")]
    prev = [_f("B", "/y", status="validated")]
    d = diff_findings(cur, prev)
    assert d["new"] == [] and d["persisting"] == [("b", "/y")]


def test_endpoint_path_normalized():
    from owlforge.report.diff import diff_findings
    cur = [_f("X", "https://t/orders/1/")]
    prev = [_f("X", "https://t/orders/1")]
    assert diff_findings(cur, prev)["persisting"] == [("x", "/orders/1")]
