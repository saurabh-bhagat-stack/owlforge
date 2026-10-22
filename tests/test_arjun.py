"""arjun hidden-parameter discovery (parsing + bounded run, graceful if absent)."""
from __future__ import annotations

import json
from types import SimpleNamespace

from owlforge.engine.recon import _arjun_params, arjun_param_discovery


def test_arjun_params_shapes():
    assert set(_arjun_params({"params": ["a", "b"]})) == {"a", "b"}
    assert set(_arjun_params({"http://t/x": {"params": ["id", "q"]}})) == {"id", "q"}
    assert set(_arjun_params([{"params": ["z"]}])) == {"z"}
    assert _arjun_params({"nope": 1}) == []


class _SB:
    def __init__(self, stdout="", exit_code=0, stderr=""):
        self._out, self._ec, self._err = stdout, exit_code, stderr
        self.cmds = []

    def exec(self, command, *, workdir=None, timeout_ms=60000, bypass_proxy=False):
        self.cmds.append(command)
        return SimpleNamespace(stdout=self._out, exit_code=self._ec, stderr=self._err)


_INV = [{"url": "http://t/search", "method": "GET", "params": [], "source": "link"}]


def test_arjun_discovers_params():
    sb = _SB(stdout=json.dumps({"http://t/search": {"params": ["id", "redirect"]}}))
    out = arjun_param_discovery("http://t", _INV, sb)
    assert len(out) == 1
    assert out[0]["source"] == "arjun" and set(out[0]["params"]) == {"id", "redirect"}
    assert "arjun -u 'http://t/search'" in sb.cmds[0]


def test_arjun_missing_tool_is_silent():
    sb = _SB(stdout="", exit_code=127, stderr="arjun: command not found")
    assert arjun_param_discovery("http://t", _INV, sb) == []


def test_arjun_no_sandbox():
    assert arjun_param_discovery("http://t", _INV, None) == []


def test_arjun_caps_endpoints():
    many = [{"url": f"http://t/e{i}", "method": "GET", "params": [], "source": "link"} for i in range(10)]
    sb = _SB(stdout=json.dumps({"params": []}))
    arjun_param_discovery("http://t", many, sb, cap=3)
    assert len(sb.cmds) == 3  # bounded
