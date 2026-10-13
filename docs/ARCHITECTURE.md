# owlforge — Architecture & Design

> Status: **design locked, pre-scaffold.** This is the blueprint for the from-scratch
> rebuild. The old Strix-port prototype lives in `owlforge-legacy` as a reference only.

## 1. What owlforge is

A **local-first, autonomous, agentic penetration-testing platform**. You give it a
project, a target, and plain-language mission instructions; a local LLM drives a team
of agents that plan, execute real tools in an isolated sandbox, validate findings with
reproducible proof, and produce a report — with a full evidence trail.

**Original work.** We study the best ideas across the field (Strix's sandboxed
tool execution, XBOW's autonomy, Shannon/XalgoriX's strengths) and re-express them as
our own architecture. We do not fork or vendor their code.

### Principles
1. **Local-first.** Any OpenAI-compatible local model must work (Jan / Ollama /
   LM Studio / llama.cpp). Hosted models are optional and only for benchmarking.
2. **Isolation with rich comms.** Tools run in our own disposable container that the
   engine talks to over a real, typed, streaming protocol — never stdout scraping.
3. **Evidence-gated.** No finding is reported without a reproducible proof-of-concept.
   Validation is a real re-test step, not an LLM assertion.
4. **Auditable & resumable.** Every event, tool call, and artifact is persisted. A
   mission can be inspected, replayed, and resumed.
5. **Small, sharp, testable.** Each layer runs and is testable on its own — the engine
   without the sandbox, the sandbox daemon without Docker, the CLI without a UI.

## 2. High-level architecture

```
+---------------------------------------------------------------+
|  owlforge engine  (Python, host process / daemon)             |
|                                                               |
|   CLI --> Orchestrator --> Agent runtime(s) --> Tool registry |
|                |                 |                   |         |
|                |            LLM layer (LiteLLM)       |         |
|                |       native-or-text tool-calling    |         |
|                |       context mgmt . structured out   |        |
|                v                                       v        |
|          SQLite store                        Sandbox RPC client |
|   (missions/agents/events/findings/report/memory)       |       |
+---------------------------------------------------------- | ----+
                                                            | HTTP + WS/SSE
                                                            | 127.0.0.1:<port>, bearer token
+---------------------------------------------------------- v ----+
|  owlforge-sandbox  (our Docker image, disposable per mission)   |
|                                                                 |
|   owlforge-agentd (daemon)   mitmproxy (capture)   tool suite   |
|     /exec (stream)            structured HTTP       nmap httpx   |
|     /files  /proxy  /health   flow history          nuclei ffuf |
|                                                     sqlmap curl  |
|   /workspace/<missionId>  (mounted volume = evidence + artifacts)|
+-----------------------------------------------------------------+
```

## 3. Engine (Python)

### 3.1 LLM layer — the local-first differentiator
This is where the legacy code was weakest and where we win.

- **Gateway:** an LLMClient interface with a default OpenAI-compatible impl (via the
  `openai` SDK) that covers every local server. A LiteLLM-backed impl can drop in
  behind the same interface later for hosted multi-provider use. [Implemented, Phase 1.]
- **Tool-calling with fallback:** try the server's *native* function-calling first; if
  the model/server doesn't support it reliably (common for local llama.cpp/Ollama),
  fall back to a **strict text tool-call protocol** (a documented JSON block in the
  prompt + a robust parser). The agent loop is identical either way.
- **Structured output:** pydantic models + `instructor` for findings/reports/plans, so
  we get typed objects, not hope-it's-valid JSON.
- **Context management:** token-aware. Keep a rolling summary of old tool output,
  hard-cap per-tool-result size, and trim the message history to fit the model's real
  context window (configurable; local models are small). The legacy code grew messages
  unbounded — a top cause of hangs/overflows.
- **Resilience:** per-call timeout, bounded retries with backoff, streaming tokens for
  live CLI output.

### 3.2 Orchestrator
An async supervisor owning one mission end-to-end. Spawns and schedules agents as
asyncio tasks, owns the `AgentGraph` (hierarchy + status), routes inter-agent messages
over asyncio queues, enforces global budget (max turns / time / token spend), and drives
the mission phases. **No "fire-and-forget promise in a web handler"** like the legacy —
the engine is a real long-lived process (CLI foreground or a local daemon).

### 3.3 Agent runtime
The think -> act -> observe loop. A typed **tool registry**; each agent gets only the
tools + skills its task needs. Per-agent scratchpad/notes/todos persisted to SQLite
(not in-memory maps that die with the process). Agents finish by emitting a typed
completion report back to the parent.

### 3.4 Tools
Thin, typed wrappers. Two kinds:
- **Sandbox tools** -> call `owlforge-agentd` over RPC: `exec_command` (streamed),
  file read/write, proxy control, HTTP history query.
- **Engine-local tools:** `spawn_agent`, `send_message`, `create_finding`,
  `web_search` (pluggable provider — NOT z.ai), `finish`.

### 3.5 Knowledge / skills
Port the legacy **skills catalog** (IDOR, SQLi, SSRF, XSS, JWT, CSRF, business-logic +
tool playbooks for httpx/katana/sqlmap/nuclei/ffuf/nmap/semgrep + framework/cloud notes)
as **data (YAML)** that feeds prompts. This is the most reusable asset in the old repo —
we keep the *content*, reimplement the *plumbing*.

### 3.6 Memory
Project-level memory (scope, creds, tech stack, prior findings, confirmed false
positives, payloads that worked) that is **written back after each mission** so the tool
gets smarter over time. The legacy read memory into prompts but never updated it.

### 3.7 Persistence
**SQLite** (via SQLModel) — one embedded, transactional store for missions, agents,
events, tool calls, findings, reports, artifacts, and project memory. Replaces *both*
the legacy JSON-file store (raced under concurrency) and the vestigial Prisma demo
models. Evidence blobs live on disk under the mission workspace; the DB holds metadata +
pointers.

## 4. Sandbox

### 4.1 Image (`owlforge-sandbox`)
Our own, built by us. Slim multi-stage build on a Debian/Kali base, pinned tool
versions, containing only: the wired tool suite, `mitmproxy`, and `owlforge-agentd`.
Entry point launches mitmproxy + the daemon and stays up — **no `set -e` death trap**
(the single biggest legacy failure). Target size: a fraction of Strix's 10.7 GB.

### 4.2 `owlforge-agentd` (in-container daemon)
A small Python service (FastAPI + uvicorn). The engine treats the sandbox as a
**service with a typed contract**, not a shell. Sketch:

| Method | Purpose |
|---|---|
| `POST /exec` -> handle | start a command; returns an id |
| `GET  /exec/{id}/stream` (SSE/WS) | live stdout/stderr |
| `GET  /exec/{id}` | final result: exit code, captured output, timing |
| `POST /processes` / `DELETE /processes/{id}` | long-running / interactive tools (listeners, crawlers) |
| `GET/PUT /files/{path}` | evidence in/out |
| `GET  /proxy/flows` | structured HTTP request/response history (from mitmproxy) |
| `POST /proxy/scope` | set capture/scope rules |
| `GET  /health` | readiness gate before a mission starts |

- **Transport:** container publishes the daemon port on `127.0.0.1:<port>` (bridge +
  `-p`). Engine talks to it over HTTP + a WS/SSE stream.
- **Auth:** engine generates a per-mission bearer token, injects it as a container env
  var; the daemon requires it. Keeps a random local port from being hijacked.
- **Testable without Docker:** the daemon runs on localhost in dev so the engine and
  tools can be exercised with no container at all.

### 4.3 Capture — mitmproxy, not Caido
mitmproxy is Python-native and scriptable (addon API) — the daemon exposes its captured
flows as structured data the engine/agents can query, diff, and replay. Cleaner and more
original than the legacy's bundled-Caido + GraphQL-guest-login approach.

### 4.4 Isolation & scope enforcement (differentiator)
Bridge network; an **egress allowlist derived from the mission scope** enforced at the
network layer inside the sandbox — so an out-of-scope request is blocked by the
environment, not just discouraged by the prompt. Workspace is a per-mission volume the
engine can read evidence from directly.

## 5. CLI (first interface)

```
owlforge run --project acme --target https://app.example.com \
             --mode standard -m "test auth + IDOR, creds in project memory"
owlforge missions [list|show <id>|resume <id>]
owlforge findings <mission-id>
owlforge report  <mission-id> [--md|--html]
owlforge sandbox [build|up|down|shell|logs]
```
Config at `~/.owlforge/config.toml` (LLM base URL/model, sandbox image/tag, budgets).
`run` streams the live event feed to the terminal.

## 6. Mission lifecycle

`recon -> plan -> execute (agents) -> validate -> report`

- **recon:** fingerprint target, seed the sitemap/scope.
- **plan:** orchestrator decomposes into parallelizable agent tasks.
- **execute:** specialized agents run tools, capture evidence, file *candidate* findings.
- **validate:** each candidate is **re-tested** with a clean PoC; only reproducible ones
  are promoted. (Evidence-gated — borrowed from the djinn philosophy.)
- **report:** executive summary + per-finding technical detail, PoC, impact, remediation,
  and the raw evidence.

## 7. Repository layout (planned)

```
owlforge/
  pyproject.toml            # engine package (owlforge)
  owlforge/
    cli.py                  # entry point
    config.py
    llm/                    # LiteLLM gateway, tool-calling, context mgmt
    engine/                 # orchestrator, agent runtime, agent graph, bus
    tools/                  # tool registry (sandbox + engine-local)
    sandbox/                # RPC client, lifecycle (build/up/down)
    knowledge/              # skills + playbooks (YAML) + loaders
    store/                  # SQLite models + repositories
    report/                 # report rendering
  sandbox/                  # the image we build
    Dockerfile
    agentd/                 # owlforge-agentd daemon source
    entrypoint.sh
  ui/                       # (later) thin dashboard over the engine's event stream
  docs/
    ARCHITECTURE.md         # this file
  tests/
  .github/workflows/        # CI: lint/test + build & push image to GHCR
```

## 8. Build / CI / registry

- **Registry:** GHCR (`ghcr.io/saurabh-bhagat-stack/owlforge-sandbox`). Private, free,
  co-located with the repo; CI authenticates with GitHub's built-in token (no secrets to
  manage). Docker Hub mirror can be added to the same workflow later for public pulls.
- **CI:** GitHub Actions — lint (ruff) + type-check (mypy/pyright) + tests (pytest) on
  every push; build & push the multi-arch sandbox image on version tags (buildx in CI
  covers the arm64+amd64 that local Docker can't).
- **Local dev:** `owlforge sandbox build` for a quick single-arch (arm64) image on the
  M4; CI owns the published multi-arch builds.

## 9. Phased roadmap

- **Phase 0 — scaffold.** Repo layout, `pyproject`, CLI skeleton (`owlforge --help`),
  config loader, SQLite models, CI (lint/test). Runnable, does nothing useful yet.
- **Phase 1 — the loop.** LLM layer (LiteLLM + tool-calling fallback + context mgmt) +
  one mock tool + a single agent. Prove the think->act->observe loop against a real local
  model, no sandbox.
- **Phase 2 — the sandbox.** Build `owlforge-sandbox` + `owlforge-agentd`; wire
  `exec_command` over RPC; single agent does real recon (httpx/nmap/curl) against a lab
  target.
- **Phase 3 — findings.** Full tool suite + mitmproxy capture + typed findings + report +
  evidence-gated validation.
- **Phase 4 — the team.** Multi-agent orchestration: spawn, coordinate, message, and
  validation agents.
- **Phase 5 — UI.** Thin dashboard over the engine's event stream.

**Testing grounds:** deliberately vulnerable web apps (e.g. ginandjuice.shop,
burpbountylab, local DVWA/Juice Shop) for the web/app-pentest flow.

## 10. What we take from `owlforge-legacy`

Keep (as content/specs, reimplemented clean): the **skills catalog**, the **system-prompt
structure**, the **finding/report schema**, and the **tool set** we decide to wire.
Drop: the Next.js-as-engine model, JSON-file store, Prisma demo models, z.ai SDK
dependency, bundled Caido, and the `set -e` entrypoint. Everything else is new.
