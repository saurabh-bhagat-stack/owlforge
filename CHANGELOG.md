# Changelog

All notable changes to owlforge are recorded here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

First tagged release. The engine runs end to end on real targets with evidence-gated,
false-positive-averse validation.

### Added
- **Autonomous pipeline:** deterministic recon (crawl, ffuf content discovery, katana,
  JS/param extraction, fingerprint, wafw00f, browser-driven interactive SPA mapping) →
  understand → auth auto-escalation (incl. login-page credential harvest, SSO/MFA via
  noVNC, RFC-6238 TOTP) → orchestrator + deterministic pre-probe → per-class specialists
  with a bypass loop → evidence-gated validation → exploit chaining → report.
- **Interactive dashboard** (`-D`): scrollable findings table, click-through detail,
  live event log; default is a scrollable streaming log (`-n` for headless CI).
- **Eager validation:** findings are confirmed per phase and surface mid-scan.
- **Knowledge packs** (`owlforge/knowledge/`): per-class / per-framework methodology
  injected into specialists, matched to recon fingerprint.
- **API-description targets:** OpenAPI/Swagger (JSON/YAML) and Postman collections.
- **Detection:** SQLi, reflected/DOM/stored XSS, access-control (IDOR + privesc), path
  traversal/LFI, SSRF, open redirect, CRLF, CSRF (deterministic token-enforcement probe),
  SSTI, RCE, NoSQL, XXE, deserialization, file-upload, GraphQL, info-disclosure,
  WebSocket, request-smuggling. OAST (SSRF/XXE/blind cmd/OOB SQLi) via interactsh →
  tunnel → bring-your-own collaborator.
- **Sandbox** (own Docker image): nmap, ffuf, nuclei, httpx, katana, wafw00f,
  interactsh, arjun (hidden-param discovery), sqlmap, Playwright Chromium, mitmproxy.
- **Reports:** Markdown, HTML, SARIF 2.1.0 with CVSS 3.1 + CWE + OWASP; cross-run diff.
- **Resumable/checkpointed runs**; provider-agnostic LLM context auto-detection.
- **CI gating:** `--fail-on <severity>` + `-n` headless + exit codes (0/1/2).
- **Sandbox image updates:** `owlforge run` does a best-effort freshness check and
  (interactively) offers to pull a newer image; `--pull`/`--no-pull` flags and
  `owlforge sandbox pull` / `owlforge sandbox update`. Default image tag is
  `:latest` (published by the release workflow).

### Notes
- Local ≤27B models validate reliably; autonomous discovery scales with model strength.
- All proof-of-impact is read-only; request-smuggling is detection-only.
