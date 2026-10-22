# owlforge — Engine & Agent Workflow (Plan of Record)

Status date: 2026-10-23. Agreed target architecture and build order for owlforge's
assessment engine. **Current status: the full pipeline below is built and in public beta**
(recon → understand → auth → plan/pre-probe → specialists → OAST → the deterministic
passes → validate → chain → report, plus the interactive dashboard and API-spec targets).
`docs/ARCHITECTURE.md` describes the system as built; `docs/recon-spec.md` is the recon
design reference.

## 0. Design principles

- **Local-first / weakest-driver.** Design for a small local model as the driver;
  a robust harness transfers to frontier models for free.
- **Deterministic detection, LLM reasoning.** Machines do discovery + signal
  detection; the model does reasoning, exploitation, judgement.
- **Evidence-gated.** Confirmed by re-test (signal re-issue, browser execution,
  cross-identity differential), never by the model's assertion.
- **Secrets are proof.** Any credential / token / key / PII we find is captured and
  shown IN FULL in the finding and report as evidence — never redacted or truncated.
- **One unified pipeline.** Unauth-first recon, auto-escalate to auth; no operator
  "mode" selection.
- **Bounded iterative loop.** Discoveries create new surface; re-plan within an
  adaptive budget until nothing new or budget exhausted.
- **Safety & scope first.** On-scope allowlist, rate limits, non-destructive proof —
  enforced throughout. (No value redaction; scope/rate/non-destruction only.)

## 1. Architecture layers

- **Transport / protocol adapters** — HTTP + GraphQL first; WebSocket + SignalR
  (Blazor) as committed later adapters. Specialists operate over an adapter.
- **Identity / Role manager** — N role-labelled sessions (unauth + userA + userB +
  low-priv + admin) for horizontal/vertical access-control testing.
- **Auth broker** — acquires each session: form-login / TOTP-seed (automated);
  SSO / push / SMS-OTP / CAPTCHA (human-in-the-loop). The interactive login runs in
  the SANDBOX's own Playwright/Chromium (already in the image), exposed to the operator
  over CDP / noVNC to complete it; owlforge then captures `storage_state` and persists it
  to a project-local file (identities yaml / .env) for reuse. Session-liveness monitor
  re-auths on expiry. No browser install on the operator's machine.
- **CSRF token manager** — transport-level fetch-extract-resubmit for rotating
  tokens (synchroniser + double-submit); header or hidden-field placement.
- **Blackboard** — annotated surface (endpoints, params, forms, JS/API routes,
  page summaries, classes, interest) + per-target attempt ledger + findings.
  This is the shared, persisted context (SQLite) — see multi-model note (§6).
- **Orchestrator** — deterministic planning (classify → per-class tasks, interest
  priority) + a deterministic pre-probe that gates which targets reach an LLM.
- **Specialist agents** — one narrow, tool-using agent per class, with an enforced
  bypass loop (encoding / alternate context / obfuscation).
- **Validators** — signal re-issue · browser-execution XSS · cross-identity
  differential (access control) · secret-actually-served (info disclosure).
- **Deepen agents** — bounded, non-destructive proof escalation on validated findings.
- **Reporter** — per-finding analysis/PoC/repro/impact/remediation with full
  evidence; CWE + OWASP tags (+ optional MITRE technique id); Markdown + HTML +
  SARIF/JSON.
- **Scope & safety guardrails** — scope resolver (see §5), rate limiting, finding
  dedupe, non-destructive constraints.

## 2. Pipeline (ordered; [det]=deterministic, [orch]=orchestrator, [agent]=LLM)

```
0. SETUP         [det]        target + IDENTITY SET + per-identity auth method + scope + sandbox
LOOP (bounded, evidence-gated, adaptive budget):
  1. RECON       [det]        crawl · ffuf · robots/sitemap · JS · OpenAPI · GraphQL probe ·
                              WS/SignalR detect · browser render · nuclei · passive signals
  2. UNDERSTAND  [det](+tiny) pages + JS + broad secret/PII scan → info-disclosure findings
                              (FULL values kept as proof); robust JS→API extraction; creds → auth
  3. AUTH        [det+human]  SESSION PER IDENTITY: form-login/TOTP-seed automated;
                              SSO/MFA/CAPTCHA via Auth Broker (headed capture); liveness re-auth
     TRANSPORT   [det]        every request carries identity session + CSRF token manager
  4. PLAN        [orch]       ORCHESTRATOR STARTS — classify → tasks (incl. login/auth, JS APIs,
                              GraphQL); per target DETERMINISTIC PRE-PROBE → only signal-positive advance
  5. HUNT        [agent]      SPECIALISTS START — tool-using + BYPASS loop; consult attempt-ledger:
                              SQLi · XSS (incl. stored) · IDOR · PrivEsc(H/V) · path/LFI · SSRF ·
                              open-redirect · SSTI · RCE/cmd · file-upload→webshell · CORS ·
                              host-header/CRLF · NoSQL · XXE · request-smuggling · deserialization ·
                              auth-logic · CSRF · GraphQL · info-disclosure
  6. VALIDATE    [det]        signal / browser-exec XSS / cross-identity differential / secret-served
  7. DEEPEN      [agent]      escalate proof on validated findings (non-destructive)
  → new surface/identities/secrets within budget? re-enter LOOP; else exit
8. REPORT        [det]        findings (full evidence) + CWE/OWASP(+MITRE tag) + recon/secrets/identity
                              appendix; Markdown + HTML + SARIF/JSON
```

Deterministic through 0–3; **orchestrator begins at step 4**; **LLM agents run in
steps 5 and 7** (optional tiny model in step 2 only to summarise a page).

## 3. Current status (as of plan date)

- **Built:** recon (crawl/ffuf/js/openapi/graphql-detect/browser-render); unified auth
  pipeline (unauth → auto-escalate; narrow credential discovery); orchestrator
  (deterministic plan + per-class dispatch + interest ordering); classified inventory;
  finish-guard; evidence gate (signal + HTML-encoded guard); browser-exec XSS verifier;
  differential access-control (authed vs anon); report builder (Markdown); sandbox
  agentd (exec/http/proxy/render/xss_check); bench.
- **Partial:** GraphQL (detect only); secret scan (JS + fixed files, 4 patterns, not
  filed, values not surfaced); access control (authed-vs-anon only, single identity).
- **Not yet:** everything in §6 milestones.

## 4. OWASP Top 10 coverage (now → planned)

| | Category | Now | Planned |
|---|---|---|---|
| A01 | Broken Access Control | partial (IDOR differential) | + multi-role horizontal/vertical privesc |
| A02 | Cryptographic Failures | ~none | cookie flags, TLS/header checks (passive) |
| A03 | Injection | SQLi + XSS | + SSTI, RCE/cmd, NoSQL, XXE, host-header/CRLF, file-upload |
| A04 | Insecure Design | n/a | n/a (not automatable) |
| A05 | Security Misconfiguration | ~none | passive layer + nuclei |
| A06 | Vulnerable Components | none | version detection + nuclei |
| A07 | Auth Failures | ~none | auth-logic, CSRF, session/JWT, SSO/MFA handling |
| A08 | Integrity Failures | none | deserialization + mass-assignment |
| A09 | Logging/Monitoring | out of scope | out of scope (not externally testable) |
| A10 | SSRF | class exists, unrun | SSRF specialist + internal-reach deepen |

MITRE: owlforge is a web-app vulnerability finder, not a full ATT&CK red-team tool.
Findings carry **CWE + OWASP** tags (+ optional ATT&CK technique id, e.g. T1190).
Mapping, not coverage.

## 5. Scope model

- `-u/--target` sets the **primary in-scope origin(s)**.
- **Auto-include** every host the app itself reaches through its own functionality,
  discovered during recon/interaction/login — a separate API origin counts (e.g.
  `abcui.com` + `abcapi.com`, or `ui.abc.com` + `api.abc.com`): whatever the app calls
  while exercising real features is in scope. Arbitrary external links are not.
- `--scope` — extra allowed hosts / path-globs / features to **include**.
- `--out-of-scope` — hosts / path-globs / features to **exclude** (exclusion wins).
- `--only <classes>` — restrict to specific vuln classes (e.g. `xss,sqli`).
- `-m/--message` — free-text in-scope / out-of-scope functionality guidance
  ("only the checkout flow", "never touch /admin").
- A **scope resolver** enforces on every outbound request (crawl, SSRF target,
  redirect follow): off-scope host/path → blocked. SSO/IdP hosts are allowed only for
  the login step, then the session is captured.

## 6. Build order (compute-light; GLM reserved for end-to-end checks)

- **M0 — Guardrails + infra.** Scope resolver, rate limiting, attempt-ledger,
  finding-dedupe, checkpoint/resume, multi-model config scaffolding. (No redaction.)
- **M1 — Understand pass.** Page/JS inspection + broad secret/PII scanner → info-
  disclosure findings with FULL values as proof; robust JS→API extraction; feed creds
  to auth.
- **M2 — Auth (pulled up).** Identity/Role manager (multi-session) + Auth Broker
  (SSO/MFA/TOTP-seed + headed session capture + liveness) + CSRF token manager
  (transport). Unblocks authenticated hunting on SSO-gated targets.
- **M3 — Passive + nuclei.** Security headers, cookie flags, dir-listing, verbose
  errors, CORS, version disclosure + nuclei signals → candidate findings / hints.
- **M4 — Pre-probe + ledger.** Deterministic per-class probe gates the LLM; wire the
  attempt-ledger into specialists.
- **M5 — Deep specialist loop + bypass.** Tool-using specialists + enforced bypass
  loop; makes existing classes (SQLi/XSS/IDOR) reliable before broadening.
- **M6 — Breadth.** SSTI · RCE/cmd · file-upload→webshell · open-redirect · SSRF ·
  CORS · host-header/CRLF · NoSQL · XXE · request-smuggling · deserialization · GraphQL
  specialist · CSRF specialist · PrivEsc (H/V) + cross-identity differential · auth-logic ·
  info-disclosure. (RCE/SSRF gated by M0 scope/rate guardrails.)
- **M7 — Loop + Deepen + stored.** Wrap PLAN→HUNT→VALIDATE→DEEPEN; re-enter on new
  surface/identity/secrets; adaptive budget; explicit stored / second-order pass
  (submit → re-crawl → re-test); non-destructive proof escalation.
- **M8 — WebSocket + Blazor/SignalR adapters.** Transport adapters so specialists run
  over WS and Blazor Server circuits; Blazor WASM assembly/boot.json → backend API.
- **M9 — Exploit-chaining + conditional.** Explicit cross-finding chaining
  (creds→auth→IDOR, SSRF→metadata→RCE) — **DONE** (engine/chains.py, non-destructive
  correlation of validated components). Remaining (best-effort): business-logic abuse
  (only partially automatable).

Beyond the milestones, also shipped: **browser-driven interactive SPA recon**
(agentd /map — drives Chromium through SPAs, captures XHR/fetch/websocket + forms),
**katana + wafw00f** recon tools, and **HTML + SARIF 2.1.0 report export** (CWE/OWASP).

Each milestone: built compute-light, unit-tested locally against known-vuln oracles
(ginandjuice + mcp-vuln-lab + Juice Shop/DVWA + others supplied at test time), with GLM
held back for a single end-to-end confirmation once a milestone lands.

### Multi-model note
Single model by default; optional per-phase model config (e.g. a cheap model for the
Understand summary, a stronger one for exploitation). **Context handover is a non-issue:**
owlforge's working context lives in the persisted blackboard + store (SQLite), not in any
model's conversation. Each phase/specialist already starts a fresh conversation seeded
from that shared state, so a different model simply reads the same blackboard. (Deeper
discussion deferred per request.)

## 7. Out of scope

- OWASP A04 (insecure design) and A09 (logging/monitoring) — not externally automatable.
- Full MITRE ATT&CK post-exploitation (lateral movement, persistence, C2).
- Thick-client / mobile / gRPC / SOAP.
- Any destructive action; owlforge is proof-only on authorized targets.

## 8. Open decisions

1. **Proof depth** — how far DEEPEN goes (e.g. SQLi: version + one row vs full table
   enum; RCE: `id`/`hostname` vs file read/write). Default: minimal unambiguous,
   read-only proof.
2. **Concurrency** — parallel specialists (faster, more model calls at once) vs
   sequential (cheaper). Default: sequential given compute limits.
3. **Identity input format** — how role-labelled credentials are supplied (identities
   file vs repeated flags).
4. **nuclei template set** — curated subset (default) vs full community set (flag).
