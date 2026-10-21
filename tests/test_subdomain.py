"""Subdomain enumeration (resolve + scope filter)."""
from __future__ import annotations

from types import SimpleNamespace


class _SB:
    """getent resolves api.* and admin.* only."""
    def exec(self, cmd, timeout_ms=0):
        out = []
        for line in ("api.example.com", "admin.example.com"):
            if line in cmd:
                out.append(line)
        return SimpleNamespace(stdout="\n".join(out) + "\n", stderr="", exit_code=0)


class _Scope:
    def __init__(self, blocked=()):
        self.blocked = blocked
    def in_scope(self, url):
        return not any(b in url for b in self.blocked)


def test_resolves_and_scopes():
    from owlforge.engine.recon import subdomain_enum
    seeds = subdomain_enum("https://www.example.com", _SB(), _Scope())
    hosts = {s.split("//")[1].rstrip("/") for s in seeds}
    assert "api.example.com" in hosts and "admin.example.com" in hosts


def test_out_of_scope_excluded():
    from owlforge.engine.recon import subdomain_enum
    seeds = subdomain_enum("https://www.example.com", _SB(), _Scope(blocked=("admin.",)))
    hosts = {s.split("//")[1].rstrip("/") for s in seeds}
    assert "api.example.com" in hosts and "admin.example.com" not in hosts


def test_noop_without_sandbox():
    from owlforge.engine.recon import subdomain_enum
    assert subdomain_enum("https://x.example.com", None) == []
