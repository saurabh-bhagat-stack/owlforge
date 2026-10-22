"""CI gate: --fail-on severity threshold decision."""
from __future__ import annotations

from owlforge.cli import _meets_fail_threshold as gate


def test_meets_threshold():
    assert gate(["high"], "high") is True
    assert gate(["critical"], "medium") is True      # above threshold
    assert gate(["low", "medium"], "high") is False  # below threshold
    assert gate([], "low") is False                  # nothing validated


def test_no_gate_when_unset_or_unknown():
    assert gate(["critical"], None) is None          # no --fail-on
    assert gate(["critical"], "") is None
    assert gate(["critical"], "bogus") is None       # unknown severity -> don't gate


def test_case_and_none_tolerant():
    assert gate(["HIGH", None, "info"], "high") is True
    assert gate([None, "low"], "medium") is False
