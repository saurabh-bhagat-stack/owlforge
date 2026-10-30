<p align="center">
  <img src="docs/assets/owlforge-banner.svg" alt="owlforge" width="760">
</p>

<p align="center">
  <img alt="tests" src="https://img.shields.io/badge/tests-353%20passing-2dd4bf">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-22d3ee">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-5b7891">
  <img alt="status" src="https://img.shields.io/badge/status-beta-f59e0b">
</p>

A **local-first, model-agnostic, autonomous web-application penetration-testing
platform**. Point it at an authorized target and a model you choose drives the whole
assessment — recon → understanding → authentication → planning → multi-agent testing →
evidence-gated validation → report — with all tooling running inside an isolated sandbox
container you build yourself.

> ⚠️ **Status: beta (testing phase).** The engine works end to end on real targets
> and is being validated across different kinds of applications; some areas are still in
> progress (see [Roadmap](#roadmap)) and interfaces/schema may change. Findings and
> recall will keep improving as testing broadens. **Only test systems you are authorized
> to assess.** Feedback and target reports are welcome via Issues.

> **Usage guide:** worked examples (authenticated IDOR, OAST config, reading results) are in [docs/USAGE.md](docs/USAGE.md).

## Demo

A live run in the interactive dashboard (the **default** on a terminal). A **narrative activity feed** tells the
story of the scan (what it's testing and why, the decisive probes, every confirmed
finding — the agent's own reasoning shown dim and tagged `thinking`, never as fact), with
live findings, a **current-target** card, the **discovered surface**, and a **steer** box
to nudge the running scan:

<p align="center">
  <img src="docs/assets/owlforge-dashboard.svg" alt="owlforge dashboard" width="820">
</p>

> _Illustrative; findings are representative of a run against a deliberately-vulnerable
> test app. Keys: ↑↓ navigate · enter/click details · `/` filter · `s` sort · `v` severity ·
> steer box always at the bottom · `L` raw log · `Ctrl+Q` quit._

Prefer plain output? `--no-dashboard` gives a scrollable streaming log (and `-n` for headless CI).

## Why local-first
owlforge is built to be driven by a **local** model (any OpenAI-compatible endpoint —
Ollama / Jan / LM Studio / llama.cpp). Designing for a modest local model forces a robust,
model-agnostic harness: the deterministic recon, pre-probe, and evidence gate do the
reliable work, so the model doesn't have to. That same harness then runs **even better on
a frontier model** through the identical OpenAI-compatible path — no special-casing.

## How it works
```
SETUP → RECON → UNDERSTAND → AUTH → SEED → PLAN → HUNT → VALIDATE → DEEPEN → dedupe → REPORT
        (always   (secrets/   (auto-  (make  (orchestr-  (special-  (evidence   (opt-in
         unauth    PII/JS→API)  escal-  test   ator +      ist +      gate)       read-only
         first)                 ate)   data)  PRE-PROBE)  scenarios)             proof)
```
- **Recon is deterministic.** A crawler + ffuf content-discovery + katana (JS-aware
  crawl) + JS/param extraction + fingerprint + wafw00f (WAF/CDN detection) map the
  surface. For JS-heavy SPAs it adds **browser-driven interactive
  recon** (real Chromium navigates routes, clicks menus/tabs, and captures every
  XHR/fetch/websocket the app makes) so dynamically-built API endpoints that never appear
  in the raw HTML are discovered too — non-destructively (it never submits forms).
- **Auth is one pipeline, not a mode.** Unauth recon runs first; owlforge then
  auto-escalates to an authenticated pass when credentials are provided, discovered
  (leaked in JS/exposed files), or **harvested from the login page**. SSO/MFA is captured
  via a headed in-sandbox browser exposed over noVNC (human-in-the-loop) and **reused on
  later runs** while still valid; TOTP is automated (RFC-6238). owlforge also detects which
  SSO provider an app uses (Google / Microsoft / Okta / Auth0 / GitHub / SAML / OIDC / …) and
  checks its OAuth2 authorization request for misconfig (missing `state`, implicit flow).
- **Planning gates the model.** The orchestrator classifies every parameter and a
  deterministic **pre-probe** tests each gateable class first; it **auto-files** findings
  it confirms itself, so recall never depends on the model remembering to file.
- **Specialists** are focused per-class agents (SQLi/XSS/SSRF/…), with an enforced
  **bypass loop** when a signal is confirmed but the agent gives up.
- **Validation is evidence-gated.** A finding is `validated` only if owlforge reproduces
  its proof — SQLi by re-issuing the structured PoC and matching the signal, **XSS by
  actual browser execution** (encoded/non-executing reflections are rejected),
  access-control by **differential testing** across identities. No model assertion counts
  as proof.
- **Found secrets, keys, and PII are reported IN FULL** as evidence — owlforge does not
  redact what it proves.
- **Exploit chaining.** After validation, owlforge correlates already-validated findings
  into higher-impact attack paths (credentialed access → IDOR/privilege escalation;
  SSRF → cloud instance metadata) — described, never further exploited.
- **Findings confirm live.** Validation runs incrementally — each specialist's findings
  are evidence-checked the moment it finishes, so confirmed issues surface mid-scan
  instead of only at the end.
- **Methodology knowledge packs.** Per-class / per-framework markdown packs
  (`owlforge/knowledge/`) are injected into the relevant specialist's prompt, matched
  to what recon fingerprinted — deepen coverage by adding a file, not code.
- **It acts like a tester, statefully.** When the app allows it, owlforge registers
  throwaway accounts (logging in two-step when sign-up needs it), creates its own test
  objects — via HTML forms, JSON APIs, multipart uploads, or GraphQL mutations — and
  captures the ids the app returns, so access-control and business-logic tests run on data
  owlforge created itself, not just what it can read.
- **Business-logic & authorization engine.** From the mapped surface, identities and seeded
  objects it builds an app model (entities / roles / workflows) and reasons over it: mass
  assignment & privilege escalation (at sign-up and on objects), client-controlled
  ownership, a cross-actor edit/delete matrix, a per-role capability matrix (forced-browsing
  / vertical privesc), workflow step-bypass, unauthenticated privileged actions, race
  conditions on single-use actions, and weak coupon validation. Provable cases are
  `validated`; intent-dependent ones are honest `candidate`s for a human to judge.
- **API-aware.** OpenAPI/Swagger (JSON/YAML) and Postman operations are tested without
  crawling: request-body fields are fuzzed as JSON, operations the spec marks protected are
  checked for missing authentication, and undocumented state-changing methods are surfaced
  via OPTIONS (non-destructively).

Vuln classes: SQLi · reflected/DOM/stored XSS · access-control (IDOR + horizontal/vertical
privesc) · path-traversal · SSRF · open-redirect · CRLF · CSRF · SSTI · RCE · NoSQL · XXE ·
deserialization · file-upload · GraphQL (incl. cross-session IDOR) · info-disclosure · WebSocket · request-smuggling · business logic (mass assignment, workflow bypass, race conditions, forced-browsing privesc) · OAuth2/OIDC misconfiguration.

**Known-CVE coverage.** Recon runs **nuclei** with its full baked template set, so known
CVEs and misconfigurations are flagged out of the box (e.g. Log4Shell, Spring4Shell,
Text4Shell, and templates for Confluence, Jira, Grafana, GitLab, WordPress, and many
more). owlforge also has a **native out-of-band Log4Shell/JNDI** check (header- and
param-based, confirmed by a DNS/LDAP callback).

See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) (plan of record), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
and [`docs/recon-spec.md`](docs/recon-spec.md).

## Requirements
- **Python 3.11+**
- **A container engine** — for the sandbox (real tool execution): Docker Desktop, [colima](https://github.com/abiosoft/colima), Rancher Desktop, **Podman**, or nerdctl. owlforge **auto-detects whichever engine is running** — no configuration needed. (To force a specific one, set `OWLFORGE_CONTAINER_ENGINE=podman`; see [Using Podman](#using-podman).)
- **An OpenAI-compatible LLM endpoint** — local (Ollama / Jan / LM Studio / llama.cpp) or hosted.

## Full setup (from scratch)
```bash
# 1. get the code
git clone https://github.com/saurabh-bhagat-stack/owlforge.git
cd owlforge

# 2. Python env + install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .                 # add ".[dev]" for tests/lint

# 3. initialize config + local DB  (writes ~/.owlforge/config.toml)
owlforge init

# 4. start your container engine (Docker Desktop / colima / Rancher Desktop / Podman)
#    — owlforge auto-detects whichever is running; the image auto-pulls on first run.

# 5. preflight — verifies engine, image, config and model, and tells you how to fix anything
owlforge doctor
#   (optional) pre-fetch the image now:  owlforge sandbox pull
#   (optional) build it from source:     owlforge sandbox build
```

### Keeping the sandbox current
When a newer sandbox image is published, `owlforge run` notices (a quick,
best-effort digest check — it never blocks and is skipped for locally-built
images or when offline) and, interactively, asks before pulling:
```bash
owlforge run app.example            # prompts [y/N] if a newer image exists
owlforge run app.example --pull     # pull the latest first, then scan
owlforge run app.example --no-pull  # skip the check entirely (offline/CI)
owlforge sandbox update             # pull only if newer; or `sandbox pull` to force
```

### Using Podman

**Usually nothing to configure** — owlforge auto-detects a running Podman. Just make sure the
Podman machine is up (`podman machine start`) and run `owlforge doctor` to confirm it's seen.

You only need the env var below to **force** Podman (e.g. you have both Docker and Podman and
want Podman). Note a shell `alias docker=podman` does **not** work — owlforge runs the CLI via
subprocess — so use the environment variable (syntax differs per shell):

| Shell | This session | Persistent |
|---|---|---|
| macOS/Linux (bash/zsh) | `export OWLFORGE_CONTAINER_ENGINE=podman` | add it to `~/.bashrc` / `~/.zshrc` |
| Windows PowerShell | `$env:OWLFORGE_CONTAINER_ENGINE = "podman"` | `setx OWLFORGE_CONTAINER_ENGINE podman` |
| Windows CMD | `set OWLFORGE_CONTAINER_ENGINE=podman` | `setx OWLFORGE_CONTAINER_ENGINE podman` |
| Git Bash / WSL | `export OWLFORGE_CONTAINER_ENGINE=podman` | add it to `~/.bashrc` |

Then make sure Podman is running and go:
```bash
podman machine init          # once (macOS/Windows; Podman runs in a small VM)
podman machine start
owlforge run http://your-target/     # auto-pulls the image via podman on first run
```
Notes for Podman users:
- `setx` / adding to your rc file only affects **new** shells — reopen the terminal, or set it
  in the **same** window you run owlforge in.
- The auto-update check uses `docker buildx imagetools inspect`, which Podman lacks, so it is
  **skipped** under Podman (no error). Update manually with `podman pull <image>:latest`.
- Alternatively, install the `podman-docker` shim (or symlink a real `docker` → `podman`) and
  skip the env var entirely.

## Configure
Edit `~/.owlforge/config.toml` and point it at your model:
```toml
[llm]
base_url = "http://127.0.0.1:11434/v1"   # e.g. Ollama's OpenAI-compatible endpoint
api_key  = "ollama"                       # any non-empty string for local servers
model    = "qwen3-14b:40k"               # a model your server actually serves
context_window = 0                        # 0 = auto-detect (Ollama); set explicitly for llama.cpp
```
> **Ollama tip:** a bare `hf.co/...` GGUF serves only ~4k context by default. Create a
> Modelfile with `PARAMETER num_ctx <N>` (matching the model's real trained window — don't
> force it larger) and `ollama create`. owlforge auto-detects the served context.
>
> **llama.cpp / hosted tip:** auto-detect only works for Ollama — set `context_window`
> explicitly to the server's context size.

## Run an assessment
The command is one argument. It runs **deep by default** — recon, interactive SPA
mapping, pre-probe, specialists, validation, and reporting, all automatic.
```bash
owlforge run ginandjuice.shop          # bare host is fine; https is assumed
owlforge run ./openapi.yaml            # or an OpenAPI/Swagger spec (json/yaml)
owlforge run ./postman_collection.json # or a Postman v2.x collection
```

By default (on a terminal) it runs in an **interactive dashboard** — a narrative activity
feed, live findings (filter/sort/drill-in), the current target, the discovered surface, and
a steer box to guide the scan as it runs. No flag needed:
```bash
owlforge run app.example                 # interactive dashboard (default)
owlforge run app.example --no-dashboard  # plain scrollable streaming log instead
owlforge run app.example -n              # headless (CI): plain output, exit codes
```
Add `-m` only to steer it — scope, credentials, focus areas, constraints. This is the
operator's highest-priority guidance and it reaches the specialists:
```bash
owlforge run app.example -m "In scope: app.example + api.example. Out of scope: */billing/*.
Creds: user alice/pass123 (role=user), admin bob/pass456 (role=admin). Focus on IDOR and
SSRF in the order/checkout flow. Rate-limit: max 5 req/s."
```
Optional knobs (each earns its place):
```bash
owlforge run app.example --identities roles.yaml   # structured multi-role creds (IDOR/privesc)
owlforge run app.example --scope api.example --out-of-scope "*/logout*"   # enforced scope boundary
owlforge run app.example --model saluki-27b:latest # override the configured model for this run
owlforge run app.example --network-recon           # also nmap (opt-in: broader authorization)
owlforge run app.example -n --fail-on high         # headless CI gate: exit 2 on >= high
```
Each run gets an auto project name `<host>-<hash>`, so repeat scans of the same domain
stay separate. A project name derives automatically — there's no `--project` to set, and
no "quick/standard" mode: owlforge is always thorough.

## Review results
```bash
owlforge assessments list          # past assessments
owlforge assessments show <id>
owlforge findings <id>             # findings for an assessment
owlforge report <id>               # markdown report (--rebuild to regenerate)
owlforge report <id> --format html # also HTML + SARIF; md|html|sarif|all
owlforge diff   <id>               # NEW / FIXED / PERSISTING vs the previous run
owlforge sandbox status            # engine + image state  (or `owlforge doctor`)
```

The report and findings are also written under the assessment's workspace directory
(`~/.owlforge/assessments/<id>/`). The sandbox (Docker) is required; if it isn't running,
owlforge tells you to start it rather than silently running a weaker host-only scan.

## Honest limitations (today)
- Local ≤27B models **confirm/validate reliably**; fully-autonomous **discovery** is less
  reliable than a frontier model — the deterministic recon + pre-probe + auto-file layer
  is what makes weak models productive. Stronger model = broader coverage, same pipeline.
- Request-smuggling is **detection-only** (low-confidence candidate; no exploitation).
- Business-logic, workflow, race-condition, forced-browsing and method-exposure checks are reported as **candidates** — their severity depends on the app's intended policy, so a human confirms them; owlforge does not fabricate `validated` for intent-dependent classes.
- Reports export to **Markdown, HTML, and SARIF 2.1.0** (CWE/OWASP-tagged for CI).
- Out of scope by design: non-web surfaces (thick-client/mobile/gRPC/SOAP), and any
  destructive action — proof is always read-only (e.g. RCE proven with `id`/`hostname`).

## Roadmap

Beta — the known gaps still being worked on:

- **White-box mode** — optional source-aware pass (secret scan + SAST) to prioritise
  dynamic testing; also unlocks PR diff-scope.
- **SSO breadth** — fully-automated sign-in for more IdPs (interactive capture stays
  human-in-the-loop by nature). Today: multi-provider detection
  (Google/Microsoft/Okta/Auth0/GitHub/SAML/OIDC/…), OAuth2/OIDC misconfiguration checks,
  form login, login-page harvest, headed noVNC capture with session reuse, and RFC-6238 TOTP.

Recently shipped (previously on this list): stateful seeding (register/login, create via
form/JSON/multipart/GraphQL); the business-logic / scenario engine (mass assignment, workflow
step-bypass, cross-actor authz, unauth-action checks, race conditions, weak coupons); a
per-role capability matrix (forced-browsing / vertical privilege escalation); full API abuse
(JSON-body injection fuzzing, schema-aware missing-auth, undocumented-method exposure);
GraphQL cross-session IDOR; SSO session reuse; and multi-provider SSO detection with OAuth2/OIDC misconfiguration checks.

## Development
```bash
pip install -e ".[dev]"
ruff check . && pytest
```

## License
MIT © saurabh-bhagat-stack — see [LICENSE](LICENSE).
