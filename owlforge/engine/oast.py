"""Out-of-band (OAST) blind-vulnerability detection via interactsh.

Blind SSRF / XXE (and blind RCE/SQLi) reflect nothing in the response — the only proof is
that the target reached out to a host the tester controls. interactsh gives us a public
callback domain: a bring-your-own self-hosted server (config `collaborator_url` [+`token`])
is tried first, else the public interactsh servers. We inject per-target tokenised payloads,
wait, then read the captured interactions and auto-file the confirmed blind findings. If no
OAST server is reachable, affected sinks are flagged as candidates that need manual
verification rather than dropped.
"""

from __future__ import annotations

import re
import secrets as _secrets
import shlex
import time
from collections.abc import Callable

from owlforge.engine.classify import SSRF, classify_param

_OUT = "/workspace/oast.jsonl"
_PAYLOAD = "/workspace/oast_payload.txt"
_STDOUT = "/workspace/oast.out"

# param names that strongly imply an SSRF/URL sink (used for the no-OAST fallback)
_SSRF_HINT = ("url", "uri", "redirect", "redir", "next", "return", "returnurl", "callback",
              "dest", "destination", "host", "feed", "webhook", "proxy", "fetch", "link",
              "page", "domain", "site", "target", "endpoint", "store", "storeid")


class OastSession:
    """Runs interactsh-client inside the sandbox and hands out tokenised callback URLs."""

    def __init__(self, sandbox, cfg):
        self.sandbox = sandbox
        self.cfg = cfg
        self.domain = ""
        self.available = False
        self.source = ""

    def start(self, log: Callable[[str], None] = lambda m: None) -> bool:
        if self.sandbox is None or not getattr(self.cfg, "enabled", True):
            return False
        server = (self.cfg.collaborator_url or self.cfg.server or "").strip()
        if not server:
            return False
        self.source = "bring-your-own" if self.cfg.collaborator_url else "public interactsh"
        tok = f" -t {shlex.quote(self.cfg.token)}" if self.cfg.token else ""
        cmd = (
            f"pkill -f interactsh-client 2>/dev/null; rm -f {_OUT} {_PAYLOAD} {_STDOUT}; "
            f"command -v interactsh-client >/dev/null 2>&1 || {{ echo __NO_INTERACTSH__; exit 0; }}; "
            f"nohup interactsh-client -server {shlex.quote(server)}{tok} -json -o {_OUT} "
            f"-ps -psf {_PAYLOAD} -pi 1 -duc -nf >{_STDOUT} 2>&1 & "
            f"sleep 5; cat {_PAYLOAD} 2>/dev/null; echo '---'; cat {_STDOUT} 2>/dev/null"
        )
        try:
            r = self.sandbox.exec(cmd, timeout_ms=25_000)
            out = (getattr(r, "stdout", "") or "")
        except Exception as e:
            log(f"oast: start failed ({e})")
            return False
        if "__NO_INTERACTSH__" in out:
            log("oast: interactsh-client not installed in the sandbox image")
            return False
        head = out.split("---", 1)[0]
        m = re.search(r"\b([a-z0-9]{20,}\.[a-z0-9.\-]+\.[a-z]{2,})\b", head)
        if not m:
            m = re.search(r"\b([a-z0-9]{20,}\.[a-z0-9.\-]+\.[a-z]{2,})\b", out)
        if not m:
            log(f"oast: no callback domain from {self.source} (server unreachable?)")
            return False
        self.domain = m.group(1)
        self.available = True
        log(f"oast: callback domain {self.domain} via {self.source}")
        return True

    def token(self) -> str:
        return "owl" + _secrets.token_hex(4)

    def url(self, token: str) -> str:
        return f"http://{token}.{self.domain}/"

    def host(self, token: str) -> str:
        return f"{token}.{self.domain}"

    def collect(self, log: Callable[[str], None] = lambda m: None) -> str:
        """Return the raw interactions text (tokens are matched by substring)."""
        try:
            r = self.sandbox.exec(f"cat {_OUT} 2>/dev/null", timeout_ms=15_000)
            return getattr(r, "stdout", "") or ""
        except Exception:
            return ""

    def stop(self) -> None:
        try:
            self.sandbox.exec("pkill -f interactsh-client 2>/dev/null; true", timeout_ms=10_000)
        except Exception:
            pass


def _file_finding(assessment_id, *, title, severity, endpoint, method, analysis, poc,
                  status, note, repro_url="", repro_method="GET", repro_params=None,
                  repro_body="", repro_content_type="", success_signal=""):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=title, severity=severity, status=status, confidence="high",
            endpoint=endpoint, method=method, technical_analysis=analysis,
            proof_of_concept=poc, impact="See the vulnerability class description.",
            remediation="Restrict/validate outbound requests and parsers; deny by default.",
            repro_url=repro_url, repro_method=repro_method, repro_params=repro_params or {},
            repro_body=repro_body, repro_content_type=repro_content_type,
            success_signal=success_signal, validation_note=note))
        s.commit()


def _ssrf_targets(inventory: list[dict]) -> list[dict]:
    """SSRF/URL sinks to OAST-test: anything classify tags SSRF, plus params whose NAME
    implies a URL/host sink (classify is conservative; OAST injection is safe + bounded, so
    we cast wider here — this is how sinks like `storeId` get tested)."""
    out = []
    for it in inventory:
        for p in it.get("params", []) or []:
            pl = p.lower()
            if SSRF in classify_param(p) or any(h in pl for h in _SSRF_HINT):
                out.append({"url": it["url"], "param": p, "method": it.get("method", "GET")})
    return out


def _xxe_endpoints(inventory: list[dict]) -> list[str]:
    seen, out = set(), []
    for it in inventory:
        if (it.get("method", "GET") or "GET").upper() in ("POST", "PUT", "PATCH"):
            if it["url"] not in seen:
                seen.add(it["url"])
                out.append(it["url"])
    return out


def oast_scan(assessment_id, inventory, sandbox, session_headers, cfg,
              log: Callable[[str], None] = lambda m: None) -> int:
    """Inject tokenised OAST payloads into SSRF params and XXE-capable endpoints, wait, then
    auto-file the blind findings that called back. Returns the count filed/flagged."""
    from owlforge.engine.preprobe import _send

    ssrf_t = _ssrf_targets(inventory)
    xxe_e = _xxe_endpoints(inventory)
    if not ssrf_t and not xxe_e:
        return 0

    sess = OastSession(sandbox, cfg)
    if not sess.start(log=log):
        # ---- no OAST reachable: flag strong SSRF sinks for manual verification ----
        flagged = 0
        for t in ssrf_t[:10]:
            if any(h in t["param"].lower() for h in _SSRF_HINT):
                _file_finding(
                    assessment_id,
                    title=f"Potential blind SSRF via '{t['param']}' (manual verification needed)",
                    severity="medium", endpoint=t["url"], method=t["method"],
                    analysis=(f"'{t['param']}' on {t['method']} {t['url']} is a URL/host sink that "
                              "could be server-side request forgery, but no OAST callback server "
                              "was reachable to confirm blind interaction."),
                    poc=f"Set {t['param']} to an attacker-controlled URL and watch for a callback.",
                    status="candidate",
                    note="potentially vulnerable — needs manual verification (no OAST reachable)")
                flagged += 1
        if flagged:
            log(f"oast: no callback server reachable — flagged {flagged} SSRF sink(s) for manual review")
        return flagged

    pending: list[dict] = []
    for t in ssrf_t[:25]:
        tok = sess.token()
        try:
            _send(sandbox, t["method"], t["url"], t["param"], sess.url(tok), session_headers)
        except Exception:
            continue
        pending.append({"token": tok, "kind": "ssrf", **t})
    for url in xxe_e[:15]:
        tok = sess.token()
        xml = ('<?xml version="1.0"?>'
               f'<!DOCTYPE r [<!ENTITY x SYSTEM "{sess.url(tok)}dtd">]><r>&x;</r>')
        h = dict(session_headers or {})
        h["Content-Type"] = "application/xml"
        try:
            sandbox.http_request("POST", url, body=xml, headers=h)
        except Exception:
            continue
        pending.append({"token": tok, "kind": "xxe", "url": url, "method": "POST"})

    log(f"oast: injected {len(pending)} callback payload(s); waiting {cfg.wait_seconds}s")
    time.sleep(max(3, int(getattr(cfg, "wait_seconds", 12))))
    interactions = sess.collect(log=log)
    sess.stop()

    filed = 0
    for p in pending:
        if p["token"] in interactions:
            if p["kind"] == "ssrf":
                _file_finding(
                    assessment_id,
                    title=f"Blind SSRF via '{p['param']}'",
                    severity="high", endpoint=p["url"], method=p["method"],
                    analysis=(f"The target fetched an attacker-controlled URL supplied in "
                              f"'{p['param']}' ({p['method']} {p['url']}): a callback to "
                              f"{sess.host(p['token'])} was received (out-of-band confirmation)."),
                    poc=f"{p['param']} = {sess.url(p['token'])} -> server-side callback received",
                    status="validated",
                    note=f"OAST callback confirmed via {sess.source}")
            else:
                _file_finding(
                    assessment_id,
                    title="Blind XML external entity (XXE) injection",
                    severity="high", endpoint=p["url"], method="POST",
                    analysis=(f"An XML external entity posted to {p['url']} caused the parser to "
                              f"fetch {sess.host(p['token'])} (out-of-band confirmation of XXE)."),
                    poc=f"XML external entity -> callback to {sess.host(p['token'])}",
                    status="validated",
                    note=f"OAST callback confirmed via {sess.source}")
            filed += 1
    if filed:
        log(f"oast: {filed} blind finding(s) confirmed by callback")
    else:
        log("oast: no callbacks received (no blind SSRF/XXE on the tested sinks)")
    return filed
