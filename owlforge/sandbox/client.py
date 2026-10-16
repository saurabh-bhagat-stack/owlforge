"""HTTP client for owlforge-agentd. The engine's view of the sandbox as a service."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


class SandboxClient:
    def __init__(self, base_url: str, token: str = "", timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def health(self) -> bool:
        try:
            r = httpx.get(f"{self.base_url}/health", timeout=5.0)
            return r.status_code == 200 and r.json().get("status") == "ok"
        except Exception:
            return False

    def exec(
        self, command: str, *, workdir: str | None = None, timeout_ms: int = 60_000, bypass_proxy: bool = False
    ) -> ExecResult:
        r = httpx.post(
            f"{self.base_url}/exec",
            headers=self._headers(),
            json={"command": command, "workdir": workdir, "timeout_ms": timeout_ms, "bypass_proxy": bypass_proxy},
            timeout=max(self.timeout, timeout_ms / 1000 + 10),
        )
        r.raise_for_status()
        d = r.json()
        return ExecResult(
            exit_code=d["exit_code"], stdout=d["stdout"], stderr=d["stderr"],
            duration_ms=d["duration_ms"], timed_out=d.get("timed_out", False),
            truncated=d.get("truncated", False),
        )

    def proxy_flows(self, limit: int = 100) -> list[dict]:
        try:
            r = httpx.get(
                f"{self.base_url}/proxy/flows",
                headers=self._headers(),
                params={"limit": limit},
                timeout=15.0,
            )
            r.raise_for_status()
            return r.json().get("flows", [])
        except Exception:
            return []

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     timeout_ms: int = 30_000) -> dict:
        r = httpx.post(
            f"{self.base_url}/http",
            headers=self._headers(),
            json={"method": method, "url": url, "headers": headers, "params": params,
                  "body": body, "timeout_ms": timeout_ms},
            timeout=max(self.timeout, timeout_ms / 1000 + 10),
        )
        r.raise_for_status()
        return r.json()

    def render(self, url: str, *, headers: dict | None = None, timeout_ms: int = 30_000) -> dict:
        r = httpx.post(
            f"{self.base_url}/render",
            headers=self._headers(),
            json={"url": url, "headers": headers, "timeout_ms": timeout_ms},
            timeout=max(self.timeout, timeout_ms / 1000 + 20),
        )
        r.raise_for_status()
        return r.json()

    def interact(self, url: str, token: str, *, headers: dict | None = None,
                 check_url: str | None = None, timeout_ms: int = 20_000) -> dict:
        """Browser-driven form interaction (fill inputs + submit + observe)."""
        r = httpx.post(f"{self.base_url}/interact", headers=self._headers(),
                       json={"url": url, "token": token, "headers": headers,
                             "check_url": check_url, "timeout_ms": timeout_ms},
                       timeout=max(self.timeout, timeout_ms / 1000 + 25))
        r.raise_for_status()
        return r.json()

    def sso_start(self, url: str, *, headers: dict | None = None) -> dict:
        """Start an interactive SSO capture (headed Chromium behind noVNC)."""
        r = httpx.post(f"{self.base_url}/sso/start", headers=self._headers(),
                       json={"url": url, "headers": headers}, timeout=90.0)
        r.raise_for_status()
        return r.json()

    def sso_finish(self, session_id: str) -> dict:
        """Capture storage_state from the live SSO session and tear it down."""
        r = httpx.post(f"{self.base_url}/sso/finish", headers=self._headers(),
                       json={"session_id": session_id}, timeout=60.0)
        r.raise_for_status()
        return r.json()

    def xss_check(self, url: str, token: str, *, headers: dict | None = None,
                  timeout_ms: int = 15_000) -> dict:
        """Confirm XSS by execution in real Chromium. Returns {executed, via, status}."""
        r = httpx.post(
            f"{self.base_url}/xss_check",
            headers=self._headers(),
            json={"url": url, "token": token, "headers": headers, "timeout_ms": timeout_ms},
            timeout=max(self.timeout, timeout_ms / 1000 + 20),
        )
        r.raise_for_status()
        return r.json()
