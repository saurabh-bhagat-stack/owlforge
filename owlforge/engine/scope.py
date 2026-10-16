"""Assessment scope — what owlforge is allowed to touch.

Primary scope is the target host from `-u`, plus every host the APP ITSELF reaches
through its own functionality (e.g. a separate `api.example.com` discovered in JS or
after login). The operator can widen/narrow with include/exclude globs and restrict to
specific vuln classes. The resolver gates every outbound request (crawl, SSRF target,
redirect follow) so the engine never wanders off-scope.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Scope:
    primary_hosts: set[str] = field(default_factory=set)   # auto-in-scope hosts
    include: list[str] = field(default_factory=list)       # extra allowed host / host-path globs
    exclude: list[str] = field(default_factory=list)       # denied globs (exclusion wins)
    only_classes: set[str] = field(default_factory=set)    # restrict vuln classes (empty = all)

    def allow_host(self, host: str) -> None:
        """Auto-include a host the app itself reached (same functionality = in scope)."""
        if host:
            self.primary_hosts.add(host.lower())

    @staticmethod
    def _host_path(url: str) -> tuple[str, str]:
        pr = urlparse(url if "://" in url else "https://" + url)
        return (pr.netloc.lower(), pr.path or "/")

    @staticmethod
    def _match(pattern: str, host: str, path: str) -> bool:
        pattern = pattern.strip().lower()
        if not pattern:
            return False
        if pattern.startswith("/"):                       # path-only glob (any host)
            return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern.rstrip("/") + "/*")
        if "/" in pattern:                                # host + path glob
            hp = host + path
            return fnmatch.fnmatch(hp, pattern) or fnmatch.fnmatch(hp, pattern.rstrip("/") + "/*")
        return fnmatch.fnmatch(host, pattern)             # host glob

    def in_scope(self, url: str) -> bool:
        host, path = self._host_path(url)
        if not host:
            return False
        for e in self.exclude:
            if self._match(e, host, path):
                return False
        if host in self.primary_hosts:
            return True
        return any(self._match(i, host, path) for i in self.include)

    def allows_class(self, cls: str) -> bool:
        return not self.only_classes or cls in self.only_classes


def build_scope(target: str, *, scope: list[str] | None = None,
                out_of_scope: list[str] | None = None, only: list[str] | None = None) -> Scope:
    """Build a Scope from the target plus operator include/exclude/only lists."""
    host, _ = Scope._host_path(target)
    return Scope(
        primary_hosts={host} if host else set(),
        include=[s.strip() for s in (scope or []) if s.strip()],
        exclude=[s.strip() for s in (out_of_scope or []) if s.strip()],
        only_classes={c.strip().lower() for c in (only or []) if c.strip()},
    )
