"""katana crawl + wafw00f parsing (offline, fake sandbox client)."""

from __future__ import annotations

import json
from types import SimpleNamespace

from owlforge.engine.recon import katana_crawl, waf_detect


class _SB:
    def __init__(self, stdout):
        self._stdout = stdout
        self.last_cmd = None

    def exec(self, cmd, timeout_ms=0):
        self.last_cmd = cmd
        return SimpleNamespace(stdout=self._stdout, stderr="", exit_code=0)


def test_katana_parses_jsonl_same_origin_with_params():
    lines = "\n".join([
        json.dumps({"request": {"method": "GET", "endpoint": "https://t.example/a?x=1"}}),
        json.dumps({"request": {"method": "POST", "endpoint": "https://t.example/api/do"}}),
        json.dumps({"request": {"method": "GET", "endpoint": "https://other.com/offsite"}}),
        "not-json-noise",
    ])
    sb = _SB(lines)
    out = katana_crawl("https://t.example/", sb, session_headers={"Cookie": "s=1"})
    by = {(i["method"], i["url"]): i for i in out}
    assert ("GET", "https://t.example/a") in by
    assert by[("GET", "https://t.example/a")]["params"] == ["x"]
    assert by[("GET", "https://t.example/a")]["source"] == "katana"
    assert ("POST", "https://t.example/api/do") in by
    assert all("other.com" not in i["url"] for i in out)  # off-origin dropped
    assert "-H 'Cookie: s=1'" in sb.last_cmd  # auth forwarded


def test_katana_noop_without_sandbox():
    assert katana_crawl("https://t/", None) == []


def test_waf_detect_reports_firewall():
    data = json.dumps([{"url": "https://t/", "detected": True,
                        "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}])
    assert waf_detect("https://t/", _SB(data)) == "Cloudflare (Cloudflare Inc.)"


def test_waf_detect_none_when_undetected():
    data = json.dumps([{"url": "https://t/", "detected": False,
                        "firewall": "None", "manufacturer": "None"}])
    assert waf_detect("https://t/", _SB(data)) == ""
    assert waf_detect("https://t/", None) == ""
