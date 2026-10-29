"""The sandbox reaper removes containers whose owner process is gone, never live ones."""
from __future__ import annotations

import os


class _R:
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


def _patch(monkeypatch, ps_out, rm_calls):
    import owlforge.sandbox.manager as m

    def fake_run(args, timeout=None):
        if "ps" in args:
            return _R(0, ps_out)
        if "rm" in args:
            rm_calls.append(args[-1])
            return _R(0)
        return _R(0)
    monkeypatch.setattr(m, "_run", fake_run)
    monkeypatch.setattr(m, "container_engine", lambda: "docker")
    return m


def test_reaps_dead_owner_keeps_live(monkeypatch):
    dead, live = 2147480000, os.getpid()      # a pid that does not exist, and this process
    rm = []
    m = _patch(monkeypatch, f"owlforge-dead\t{dead}\t100\nowlforge-live\t{live}\t200\n", rm)
    n = m.reap_orphans(log=lambda x: None)
    assert n == 1
    assert rm == ["owlforge-dead"]            # only the dead-owner container removed


def test_unlabelled_container_reaped_only_when_old(monkeypatch):
    import time
    now = int(time.time())
    rm = []
    # no pid label; one fresh (kept) and one ancient (reaped) via the age fallback
    out = f"owlforge-fresh\t\t{now - 60}\nowlforge-ancient\t\t{now - 3 * 24 * 3600}\n"
    m = _patch(monkeypatch, out, rm)
    n = m.reap_orphans(log=lambda x: None, max_age_h=24.0)
    assert n == 1 and rm == ["owlforge-ancient"]


def test_no_containers_no_removals(monkeypatch):
    rm = []
    m = _patch(monkeypatch, "", rm)
    assert m.reap_orphans(log=lambda x: None) == 0
    assert rm == []
