# owlforge — Architecture & Design

owlforge is a **local-first, model-agnostic, autonomous web-application penetration-testing
platform**. You give it an authorized target and plain-language instructions; a model you
choose drives recon → understanding → authentication → planning → multi-agent testing →
evidence-gated validation → reporting, with all tooling running inside an isolated sandbox
container and a full evidence trail persisted to SQLite.

This document describes the system as built. The agreed engine/agent workflow and the
milestone build order live in [`WORKFLOW.md`](WORKFLOW.md); the recon design in
[`recon-spec.md`](recon-spec.md).

## 1. Design principles

1. **Local-first, model-agnostic.** Any OpenAI-compatible endpoint works (Ollama / Jan /
   LM Studio / llama.cpp, or a hosted API). Designing for a modest local model forces a
   robust harness — the deterministic recon, pre-probe, and evidence gate do the reliable
   work — which then runs even better on a stronger model through the identical path.
2. **Isolation with a typed contract.** Tools run in a disposable container the engine
   talks to over a real, typed HTTP protocol — never stdout scraping.
3. **Evidence-gated.** No finding is reported without a reproducible proof. Validation is a
   real re-test step (re-issue the PoC, match the signal; XSS confirmed by browser
   execution), not a model assertion.
4. **Deterministic where it counts.** Crawling, surface enumeration, and per-class probing
   are deterministic; the model spends its turns testing a mapped surface, not trying to
   remember to enumerate.
5. **Non-destructive.** Proof is read-only (e.g. RCE shown with `id`/`hostname`); nothing
   mutating, no data exfiltration, no DoS.
6. **Auditable & resumable.** Every event, tool call, attempt, and artifact is persisted;
   working context lives in the store, not model memory.
7. **Small, sharp, testable.** Each layer runs on its own — the engine without the sandbox,
   the sandbox daemon without Docker, the CLI without a UI.

## 2. High-level architecture

```
+---------------------------------------------------------------+
|  owlforge engine  (Python, host process)                      |
|                                                               |
|   CLI --> run_recon --> orchestrator --> specialist agents    |
|              |              |                  |              |
|              |         pre-probe (gates the model, auto-files)|
|              |         LLM client (OpenAI-compatible)          |
|              |         native-or-text tool-calling, ctx mgmt   |
|              v                                  v              |
|          SQLite store                   Sandbox RPC client     |
|   (assessments/findings/surface/attempts/events/report)       |
+---------------------------------------------------------- | --+
                                                            | HTTP, 127.0.0.1:<port>, bearer token
+---------------------------------------------------------- v --+
|  owlforge-sandbox  (our Docker image, disposable per run)     |
|                                                               |
|   owlforge-agentd (FastAPI daemon)   mitmproxy (capture)      |
|     /exec /http /file /proxy/flows   Playwright Chromium:      |
|     /render /map /xss_check          /render /map /interact   |
|     /interact /sso/* /ws_probe       tool suite: nmap httpx    |
|     /smuggle_probe /health           nuclei ffuf katana wafw00f|
|   /workspace  (mounted volume = evidence + artifacts)         |
+---------------------------------------------------------------+
```

## 3. Engine (Python)

### 3.1 LLM layer — the local-first core
An `LLMClient` interface with a default OpenAI-compatible implementation (via the `openai`
SDK) that covers every local and hosted server. It tries the server's **native**
function-calling first and falls back to a **strict text tool-call protocol** (a documented
JSON block + a robust balanced-brace parser) when native support is unreliable — common for
local llama.cpp/Ollama. Reasoning/`<think>` content is stripped. Context is token-aware:
per-tool-result caps, trimming that pins the system + first user message and fills the
newest tail, and compaction of dropped turns — so long runs don't overflow a small window.

### 3.2 Recon (deterministic)
`run_recon` runs unauthenticated first, then auto-escalates to an authenticated pass when
credentials are provided, discovered (leaked in JS/exposed files), or harvested from the
login page. Each pass builds an attack-surface inventory: crawl + ffuf content-discovery +
JS→API extraction + OpenAPI/GraphQL probes + fingerprint + WAF detection (wafw00f) + a
deep JS-aware crawl (katana). For JS-heavy SPAs it adds **browser-driven interactive
mapping** (`/map`): real Chromium navigates routes and clicks disclosure/nav controls while
a request listener captures every XHR/fetch/websocket the app makes — recovering
dynamically-built endpoints that never appear in the raw HTML. Non-destructive throughout.

### 3.3 Understanding & authentication
A broad secret/PII scanner surfaces exposed credentials, keys, and tokens (kept in full as
evidence). The identity/role manager supports multiple labelled sessions (unauth / user A /
user B / low / admin) via cookie, header, form-login, or TOTP (RFC-6238, dependency-free).
SSO/MFA is captured by a headed in-sandbox browser exposed over noVNC for a human-in-the-loop
sign-in, whose storage state is then reused.

### 3.4 Planning & pre-probe
The orchestrator classifies every parameter and endpoint into vulnerability classes and
builds a prioritized task list. A deterministic **pre-probe** tests each gateable class
first; it **auto-files** findings it confirms itself, so recall never depends on the model
remembering to file, and it skips classes with no signal so breadth doesn't inflate runtime.

### 3.5 Specialist agents
Each task is handled by a focused per-class agent (SQLi, XSS, SSRF, path-traversal, SSTI,
RCE, access-control, …) with a think→act→observe loop and only the tools and playbook its
task needs. When a signal is confirmed but an agent gives up, an enforced bypass loop
re-prompts once with concrete evasion techniques, informed by the attempt ledger.

### 3.6 Validation, dedupe, chaining, report
Validation re-issues each candidate's structured PoC and promotes it only if the success
signal reproduces; XSS is confirmed by actual browser execution; access-control by
differential testing across identities. Findings are deduped; an exploit-chain pass
correlates already-validated components into higher-impact narratives (credentialed
access → IDOR/privilege escalation; SSRF → cloud instance metadata) — described, never
further exploited. Reports render to Markdown, HTML, and SARIF 2.1.0 (CWE/OWASP-tagged).

### 3.7 Knowledge / playbooks
Per-class methodology and tool invocations as **data** (`owlforge/knowledge/playbooks/*.yaml`)
rendered into the relevant agent's prompt.

### 3.8 Persistence
One embedded, transactional **SQLite** store (via SQLModel) for assessments, surface items,
findings, attempts, events, and reports. Evidence blobs live on disk under the assessment
workspace; the DB holds metadata and pointers. Schema upgrades are additive.

## 4. Sandbox

### 4.1 Image (`owlforge-sandbox`)
A slim multi-stage build on a Debian base with pinned tool versions: the recon/test tool
suite (nmap, httpx, nuclei, ffuf, katana, wafw00f), `mitmproxy`, Playwright Chromium, a
noVNC stack for interactive sign-in, and `owlforge-agentd`. The entry point launches the
capture proxy and the daemon and stays up (no `set -e`). Agentd code is copied last so
editing it rebuilds in seconds.

### 4.2 `owlforge-agentd` (in-container daemon)
A small FastAPI service. The engine treats the sandbox as a **service with a typed
contract**, not a shell:

| Endpoint | Purpose |
|---|---|
| `GET /health` | readiness gate before a run starts |
| `POST /exec` | run a command; exit code, captured output, timing |
| `POST /http` | structured HTTP request (no shell quoting) |
| `GET /file` | read evidence from the workspace |
| `GET /proxy/flows` | structured HTTP history from mitmproxy |
| `POST /render` | headless-Chromium render (runs JS, returns the DOM) |
| `POST /map` | interactive SPA crawl: navigate + click, capture XHR/fetch/WS |
| `POST /xss_check` | confirm XSS by real browser execution |
| `POST /interact` | fill + submit for formless/stored XSS |
| `POST /sso/start` · `POST /sso/finish` | headed-browser SSO/MFA capture over noVNC |
| `POST /ws_probe` | WebSocket connect/send/receive |
| `POST /smuggle_probe` | time-based request-smuggling detection |

- **Transport:** the container publishes the daemon port on `127.0.0.1:<port>`; the engine
  talks to it over HTTP.
- **Auth:** the engine generates a per-run bearer token and injects it as a container env
  var; the daemon requires it, so a random local port can't be hijacked.
- **Testable without Docker:** the daemon runs on localhost in dev, so the engine and tools
  can be exercised with no container.

### 4.3 Capture
`mitmproxy` is Python-native and scriptable; the daemon exposes its captured flows as
structured data the engine and agents can query, diff, and replay.

### 4.4 Scope enforcement
A scope resolver (primary host + the app's own API/SSO hosts, with `--scope` / `--out-of-scope`
/ `--only`) gates every request and the orchestrator's class/target selection, so
out-of-scope traffic is blocked rather than merely discouraged.

## 5. CLI

```
owlforge init
owlforge sandbox build | status
owlforge run --target https://app.example --project acme -m "full assessment" \
             [--browser-recon] [--identities ids.yaml] [--scope h] [--only xss,sqli] \
             [--nuclei] [--deepen] [--single]
owlforge assessments list | show <id>
owlforge findings <id>
owlforge report  <id> [--format md|html|sarif|all] [--rebuild]
```
Config lives at `~/.owlforge/config.toml` (LLM base URL / model, sandbox image, budgets).
`run` streams the live event feed to the terminal.

## 6. Repository layout

```
owlforge/
  pyproject.toml
  owlforge/
    cli.py  config.py
    llm/            # OpenAI-compatible client, tool-calling, context mgmt
    engine/         # recon, orchestrator, agents, pre-probe, validate, chains, ...
    tools/          # tool registry (sandbox + engine-local)
    sandbox/        # RPC client, container lifecycle
    knowledge/      # playbooks (YAML) + loader
    store/          # SQLite models
    report/         # markdown / HTML / SARIF rendering
    bench/          # model-compatibility benchmarking (dev)
  sandbox/          # the image we build (Dockerfile, agentd/, entrypoint.sh, wordlists/)
  docs/             # ARCHITECTURE.md, WORKFLOW.md, recon-spec.md
  tests/
  .github/workflows/  # CI: lint + test; build & push image to GHCR
```

## 7. Build / CI / registry

- **Registry:** GHCR (`ghcr.io/saurabh-bhagat-stack/owlforge-sandbox`); CI authenticates
  with GitHub's built-in token.
- **CI:** GitHub Actions — ruff + pytest on every push; multi-arch image build on version
  tags (buildx covers arm64 + amd64).
- **Local dev:** `owlforge sandbox build` for a single-arch image; CI owns the published
  multi-arch builds.

## 8. Testing

Each layer is unit-tested; the full pipeline is validated against deliberately vulnerable
web apps that the operator is authorized to assess (targets are supplied at test time).
