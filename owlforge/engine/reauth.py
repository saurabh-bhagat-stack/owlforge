"""Transparent mid-scan re-authentication.

A long authenticated run can outlive its session (idle timeout, rotated JWT). Without this
the scan silently degrades to anonymous halfway through and every later finding is missed.
ReauthSandbox wraps the sandbox client: when an AUTHENTICATED request comes back as a dead
session (401/403, a redirect to login, or a login form in a 200 body), it re-logs-in from the
saved spec (fresh TOTP), updates the shared session-headers dict IN PLACE so every later
scanner sees the new session, and retries the request once. Anonymous requests are left alone
(so access-control's deliberate anon probes are never "fixed"). A cooldown prevents hammering.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class ReauthSandbox:
    def __init__(self, inner, session_headers: dict, login_specs: list[dict],
                 log: Callable[[str], None] = lambda m: None, cooldown_s: float = 90.0):
        self._inner = inner
        self._sh = session_headers if session_headers is not None else {}
        self._specs = login_specs or []
        self._log = log
        self._cooldown_s = cooldown_s
        self._until = 0.0

    def __getattr__(self, name):          # delegate render/exec/xss_check/browser_login/…
        return getattr(self._inner, name)

    def _reqfn(self, method, url, headers=None, params=None, body=None):
        try:
            return self._inner.http_request(method, url, headers=headers, params=params, body=body)
        except Exception:
            return {}

    @staticmethod
    def _dead_session(r: dict) -> bool:
        st = int((r or {}).get("status") or 0)
        if st in (401, 403):
            return True
        hdrs = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()} if r else {}
        if 300 <= st < 400:
            loc = hdrs.get("location", "").lower()
            return "login" in loc or "signin" in loc
        if st == 200:
            try:
                from owlforge.engine.validate import _looks_like_login
                return bool(_looks_like_login(r.get("body") or ""))
            except Exception:
                return False
        return False

    def _refresh(self) -> bool:
        if not self._specs or time.monotonic() < self._until:
            return False
        from owlforge.engine.identities import reauth_login
        fresh = reauth_login(self._specs[0], self._reqfn, log=self._log) or {}
        if fresh:
            self._sh.clear()
            self._sh.update(fresh)
            self._log("[reauth] session expired mid-scan — refreshed and continuing")
            return True
        self._until = time.monotonic() + self._cooldown_s
        self._log("[reauth] session expired but automatic re-login failed")
        return False

    def http_request(self, method, url, *, headers=None, params=None, body=None, **kw):
        r = self._inner.http_request(method, url, headers=headers, params=params, body=body, **kw)
        # Act only when THIS request carried our session, so deliberately-anonymous probes
        # (e.g. access-control's anon identity) are never "repaired" into authenticated ones.
        carried = bool(headers) and bool(self._sh) and any(k in (headers or {}) for k in self._sh)
        if carried and self._dead_session(r) and self._refresh():
            h2 = dict(headers or {})
            h2.update(self._sh)
            r = self._inner.http_request(method, url, headers=h2, params=params, body=body, **kw)
        return r
