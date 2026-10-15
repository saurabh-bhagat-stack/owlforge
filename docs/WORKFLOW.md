# owlforge — Engine & Agent Workflow (Plan of Record)

Status date: 2026-10-16. This is the agreed target architecture and build order for
owlforge's assessment engine. It supersedes ad-hoc notes; `docs/ARCHITECTURE.md` and
`docs/recon-spec.md` remain the lower-level references.

## 0. Design principles

- **Local-first / weakest-driver.** Design for a small local model as the driver; a
  robust harness then transfers to frontier models for free.
- **Deterministic detection, LLM reasoning.** Machines do mechanical discovery and
  signal detection; the model does reasoning, exploitation, and judgement.
- **Evidence-gated.** A finding is confirmed by re-test (signal re-issue, browser
  execution, cross-identity differential), never by the model's assertion.
- **One unified pipeline.** Unauth-first recon, auto-escalate to auth; no operator
  "mode" selection.
- **Bounded iterative loop.** Discoveries create new surface; re-plan within an
  adaptive budget until nothing new or budget exhausted.
- **Safety & scope first.** On-scope allowlist, rate limits, non-destructive proof,
  secret redaction — enforced throughout.

## 1. Architecture layers

- **Transport / protocol adapters** — HTTP (now); GraphQL (near); WebSocket + SignalR
  (Blazor) (deferred). Specialists operate over an adapter, not raw HTTP only.
- **Identity / Role manager** — N role-labelled sessions (unauth + userA + userB +
  low-priv + admin). Enables horizontal/vertical access-control testing.
- **Auth broker** — acquires each session: form-login / TOTP-seed (automated),
  SSO / push / SMS-OTP / CAPTCHA (human-in-the-loop via headed browser +
  storage_state capture), session-liveness monitor (re-auth on expiry).
- **CSRF token manager** — transport-level fetch-extract-resubmit for rotating
  tokens (synchroniser + double-submit); header or hidden-field placement.
- **Blackboard** — annotated surface (endpoints, params, forms, JS/API routes,
  page summaries, classes, interest) + per-target attempt ledger + findings.
- **Orchestrator** — deterministic planning (classify → per-class tasks, interest
  priority) + deterministic pre-probe that gates which targets reach an LLM.
- **Specialist agents** — one narrow, tool-using agent per vuln class, with an
  enforced bypass loop (encoding / alternate context / obfuscation).
- **Validators** — signal re-issue · browser-execution XSS · cross-identity
  differential (access control) · secret-actually-served (info disclosure).
- **Deepen agents** — bounded, non-destructive proof escalation on validated
  findings (version/db enum, cross-user data, internal reach).
- **Reporter** — per-finding analysis/PoC/repro/impact/remediation; CWE + OWASP
  tags (+ optional MITRE technique id); Markdown now, JSON/SARIF for CI later.
- **Guardrails** — scope allowlist, rate limiting, secret redaction, finding dedupe.

## 2. Pipeline (ordered; [det]=deterministic, [orch]=orchestrator, [agent]=LLM)

```
0. SETUP         [det]        target + IDENTITY SET + per-identity auth method + flags + sandbox
LOOP (bounded, evidence-gated, adaptive budget):
  1. RECON       [det]        crawl · ffuf · robots/sitemap · JS · OpenAPI · GraphQL probe ·
                              WS/SignalR detect · browser render · nuclei · passive signals
  2. UNDERSTAND  [det](+tiny) pages + JS + broad secret/PII scan → info-disclosure findings;
                              robust JS→API extraction; usable creds → auth
  3. AUTH        [det+human]  a SESSION PER IDENTITY: form-login/TOTP-seed automated;
                              SSO/MFA/CAPTCHA via Auth Broker (headed capture); liveness re-auth
     TRANSPORT   [det]        every request carries identity session + CSRF token manager
  4. PLAN        [orch]       ORCHESTRATOR STARTS — classify → tasks (incl. login/auth, JS APIs,
                              GraphQL); per target DETERMINISTIC PRE-PROBE → only signal-positive advance
  5. HUNT        [agent]      SPECIALISTS START — tool-using + BYPASS loop; consult attempt-ledger:
                              SQLi · XSS · IDOR · PrivEsc(H/V) · path/LFI · SSRF · open-redirect ·
                              SSTI · RCE/cmd · CORS · host-header/CRLF · file-upload · NoSQL ·
                              auth-logic · CSRF · GraphQL · info-disclosure
  6. VALIDATE    [det]        signal / browser-exec XSS / cross-identity differential / secret-served
  7. DEEPEN      [agent]      escalate proof on validated findings (non-destructive)
  → new surface/identities/secrets within budget? re-enter LOOP; else exit
8. REPORT        [det]        findings + CWE/OWASP(+MITRE tag) + recon/secrets/identity appendix
```

Deterministic through steps 0–3; the **orchestrator begins at step 4**; **LLM agents
run in steps 5 and 7** (an optional tiny model in step 2 only to summarise a page).

## 3. Current status (as of plan date)

- **Built:** recon (crawl/ffuf/js/openapi/graphql-detect/browser-render); unified
  auth pipeline (unauth → auto-escalate; narrow credential discovery); orchestrator
  (deterministic plan + per-class dispatch + interest ordering); classified inventory;
  finish-guard; evidence gate (signal + HTML-encoded guard); browser-exec XSS verifier;
  differential access-control (authed vs anon); report builder; sandbox agentd
  (exec/http/proxy/render/xss_check); bench.
- **Partial:** GraphQL (detect only, no attack); secret/credential scan (JS + fixed
  files, 4 patterns, not filed as findings); access control (authed-vs-anon only, no
  multi-identity).
- **Not yet:** everything in the milestones below.

## 4. OWASP Top 10 coverage (now → planned)

| | Category | Now | Planned |
|---|---|---|---|
| A01 | Broken Access Control | partial (IDOR differential) | + multi-role horizontal/vertical privesc |
| A02 | Cryptographic Failures | ~none | cookie flags, TLS/header checks (passive) |
| A03 | Injection | SQLi + XSS | + SSTI, RCE/cmd, NoSQL, host-header/CRLF |
| A04 | Insecure Design | n/a | n/a (not automatable) |
| A05 | Security Misconfiguration | ~none | passive layer + nuclei |
| A06 | Vulnerable Components | none | version detection + nuclei |
| A07 | Auth Failures | ~none | auth-logic specialist, CSRF, session/JWT |
| A08 | Integrity Failures | none | deserialization/mass-assignment (partial) |
| A09 | Logging/Monitoring | out of scope | out of scope (not externally testable) |
| A10 | SSRF | class exists, unrun | SSRF specialist + internal-reach deepen |

MITRE: owlforge is a web-app vulnerability finder, not a full ATT&CK red-team tool.
Findings are tagged with **CWE + OWASP** and optionally a relevant ATT&CK technique
id (e.g. T1190); this is mapping, not coverage.

## 5. Protocol / technology coverage

- **HTTP** — core, built.
- **GraphQL** — detection built; attack specialist planned (M5).
- **WebSocket** — deferred adapter (M9): discovery + message injection + auth-over-WS.
- **Blazor** — deferred (M9): Server = SignalR/WebSocket circuit; WASM = blazor.boot.json
  + compiled-assembly backend API. Needs the adapter layer.
- **SSO (Microsoft/Google/other)** — human-in-the-loop: headed browser, user completes
  SSO, owlforge captures storage_state and reuses it (M8). Never automates IdP creds.
- **OTP/MFA/TOTP** — TOTP-with-seed automated (pyotp); SMS/email/push = Auth Broker
  pauses and prompts the operator; CAPTCHA always human (M8).
- **CSRF** — rotating-token handling in transport (M8) + CSRF vulnerability specialist
  (omit/stale/replay/SameSite/Origin) (M8).

## 6. Build order (compute-light; GLM reserved for end-to-end checks)

- **M0 — Guardrails + infra.** Scope allowlist, rate limiting, secret redaction,
  attempt-ledger + finding-dedupe, per-phase model config, checkpoint/resume.
- **M1 — Understand pass.** Page/JS inspection + broad secret/PII scanner (file as
  info-disclosure findings); robust JS→API extraction; feed creds to auth.
- **M2 — Passive + nuclei.** Security headers, cookie flags, dir-listing, verbose
  errors, CORS, version disclosure + nuclei signals → candidate findings / hints.
- **M3 — Pre-probe + ledger.** Deterministic per-class probe gates the LLM; wire the
  attempt-ledger into specialists.
- **M4 — Deep specialist loop + bypass.** Tool-using specialists with an enforced
  bypass loop; makes the existing classes (SQLi/XSS/IDOR) reliable.
- **M5 — Breadth + GraphQL.** SSTI, RCE/cmd, open-redirect, SSRF, CORS,
  host-header/CRLF, file-upload, NoSQL, GraphQL specialist. (RCE/SSRF gated by M0.)
- **M6 — Identity + privesc.** Multi-session identity manager + horizontal/vertical
  privesc + cross-identity differential validator (A01).
- **M7 — Loop + Deepen.** Wrap PLAN→HUNT→VALIDATE→DEEPEN; re-enter on new
  surface/identity/secrets; adaptive budget; post-validation proof escalation.
- **M8 — Auth-Broker + CSRF.** Assisted SSO/MFA + TOTP-seed + headed session capture +
  liveness; CSRF token manager (transport) + CSRF specialist (A07). *Pull up to after
  M1 if near-term targets are SSO/MFA-gated.*
- **M9 — Deferred (named).** WebSocket + Blazor/SignalR adapters; explicit
  exploit-chaining; business-logic; subdomain/vhost enum; request smuggling;
  deserialization; XXE.

Each milestone: built compute-light, unit-tested locally against known-vuln oracles
(ginandjuice + mcp-vuln-lab / Juice Shop / DVWA), with GLM held back for a single
end-to-end confirmation once a milestone lands.

## 7. Out of scope

- OWASP A04 (insecure design) and A09 (logging/monitoring) — not externally automatable.
- Full MITRE ATT&CK post-exploitation (lateral movement, persistence, C2).
- Business-logic abuse beyond simple access-control (deferred, partial at best).
- Thick-client / mobile / gRPC / SOAP — not planned.
- Any destructive action; owlforge is proof-only on authorized targets.

## 8. Open decisions

1. **Auth-Broker timing** — are near-term targets SSO/MFA-gated? If yes, M8 → after M1.
2. **Injection breadth** — include XXE / request-smuggling / deserialization in M5, or
   leave in M9?
3. **Report formats** — add JSON/SARIF for CI alongside Markdown, and when?
4. **Benchmark oracles** — confirm ginandjuice + mcp-vuln-lab + Juice Shop/DVWA as the
   per-class validation set.
5. **Scope input** — how the operator declares in-scope hosts (allowlist file / flag).
6. **Per-phase models** — cheap model for Understand summaries, stronger for
   exploitation — confirm acceptable.
