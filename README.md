<p align="center">
  <img src="docs/assets/owlforge-banner.svg" alt="owlforge" width="760">
</p>

<p align="center">
  <img alt="tests" src="https://img.shields.io/badge/tests-229%20passing-2dd4bf">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-22d3ee">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-5b7891">
  <img alt="status" src="https://img.shields.io/badge/status-beta-f59e0b">
</p>

A **local-first, model-agnostic, autonomous web-application penetration-testing
platform**. Point it at an authorized target and a model you choose drives the whole
assessment — recon → understanding → authentication → planning → multi-agent testing →
evidence-gated validation → report — with all tooling running inside an isolated sandbox
container you build yourself.

Original work — its own architecture and engine, built from the ground up.

> ⚠️ **Status: beta (public testing phase).** The engine works end to end on real targets
> and is being validated across different kinds of applications; some areas are still in
> progress (see [Roadmap](#roadmap)) and interfaces/schema may change. Findings and
> recall will keep improving as testing broadens. **Only test systems you are authorized
> to assess.** Feedback and target reports are welcome via Issues.

> **Usage guide:** worked examples (authenticated IDOR, OAST config, reading results) are in [docs/USAGE.md](docs/USAGE.md).

## Demo

A live run in the interactive dashboard (`-D`). A **narrative activity feed** tells the
story of the scan (what it's testing and why, the decisive probes, every confirmed
finding — the agent's own reasoning shown dim and tagged `thinking`, never as fact), with
live findings, a **current-target** card, the **discovered surface**, and a **steer** box
to nudge the running scan:

<p align="center">
  <img src="docs/assets/owlforge-dashboard.svg" alt="owlforge dashboard" width="820">
</p>

> _Illustrative; findings are representative of a run against a deliberately-vulnerable
> test app. Keys: ↑↓ navigate · enter/click details · `/` filter · `s` sort · `v` severity ·
> `m`-less steer box at the bottom · `L` raw log · `Ctrl+Q` quit._

Prefer plain output? Omit `-D` for a scrollable streaming log (and `-n` for headless CI).

## Why local-first
owlforge is built to be driven by a **local** model (any OpenAI-compatible endpoint —
Ollama / Jan / LM Studio / llama.cpp). Designing for a modest local model forces a robust,
model-agnostic harness: the deterministic recon, pre-probe, and evidence gate do the
reliable work, so the model doesn't have to. That same harness then runs **even better on
a frontier model** through the identical OpenAI-compatible path — no special-casing.

## How it works
```
SETUP → RECON → UNDERSTAND → AUTH → PLAN → HUNT → VALIDATE → DEEPEN → dedupe → REPORT
        (always   (secrets/   (auto-  (orchestr-  (special-  (evidence   (opt-in
         unauth    PII/JS→API)  escal-  ator +      ist        gate)       read-only
         first)                 ate)    PRE-PROBE)  agents)                proof)
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
  via a headed in-sandbox browser exposed over noVNC (human-in-the-loop); TOTP is
  automated (RFC-6238).
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
- **Targets include API descriptions.** Point it at an OpenAPI/Swagger (JSON/YAML) or
  Postman collection and every operation is tested without crawling.

Vuln classes: SQLi · reflected/DOM/stored XSS · access-control (IDOR + horizontal/vertical
privesc) · path-traversal · SSRF · open-redirect · CRLF · CSRF · SSTI · RCE · NoSQL · XXE ·
deserialization · file-upload · GraphQL · info-disclosure · WebSocket · request-smuggling.

**Known-CVE coverage.** Recon runs **nuclei** with its full baked template set, so known
CVEs and misconfigurations are flagged out of the box (e.g. Log4Shell, Spring4Shell,
Text4Shell, and templates for Confluence, Jira, Grafana, GitLab, WordPress, and many
more). owlforge also has a **native out-of-band Log4Shell/JNDI** check (header- and
param-based, confirmed by a DNS/LDAP callback).

See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) (plan of record), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
and [`docs/recon-spec.md`](docs/recon-spec.md).

## Requirements
- **Python 3.11+**
- **A container engine** — for the sandbox (real tool execution). Docker Desktop, [colima](https://github.com/abiosoft/colima), or Rancher Desktop work out of the box. **Podman** works too: set `OWLFORGE_CONTAINER_ENGINE=podman` and owlforge calls `podman` directly (a shell `alias docker=podman` is *not* enough — owlforge runs the CLI via subprocess; the env var, the `podman-docker` shim, or a `docker`→`podman` symlink is).
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
#    the sandbox image is then pulled automatically on first run
owlforge sandbox pull            # optional: pre-fetch the published image now
#                                  (or build from source instead: owlforge sandbox build)
owlforge sandbox status          # confirm: docker available + image present
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

### Using Podman (instead of Docker)

owlforge runs the container CLI via a subprocess, so a shell `alias docker=podman` is **not**
enough. Point owlforge at podman with an environment variable — the syntax differs per shell:

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

Watch it live in an **interactive dashboard** — a narrative activity feed, live findings
(filter/sort/drill-in), the current target, the discovered surface, and a steer box to
guide the scan as it runs:
```bash
owlforge run app.example -D
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
owlforge sandbox status            # docker + image state
```

The report and findings are also written under the assessment's workspace directory
(`~/.owlforge/assessments/<id>/`). The sandbox (Docker) is required; if it isn't running,
owlforge tells you to start it rather than silently running a weaker host-only scan.

## Honest limitations (today)
- Local ≤27B models **confirm/validate reliably**; fully-autonomous **discovery** is less
  reliable than a frontier model — the deterministic recon + pre-probe + auto-file layer
  is what makes weak models productive. Stronger model = broader coverage, same pipeline.
- Request-smuggling is **detection-only** (low-confidence candidate; no exploitation).
- Reports export to **Markdown, HTML, and SARIF 2.1.0** (CWE/OWASP-tagged for CI).
- Out of scope by design: non-web surfaces (thick-client/mobile/gRPC/SOAP), and any
  destructive action — proof is always read-only (e.g. RCE proven with `id`/`hostname`).

## Roadmap

Beta — these are known gaps being worked on:

- **User roles & richer multi-identity** — deeper role modelling beyond the current
  owner/other/anon differential.
- **SSO / IdP flows** — hardening automated sign-in across more providers (today:
  form login, login-page harvest, headed noVNC for SSO/MFA, RFC-6238 TOTP).
- **Deeper API scanning** — beyond OpenAPI/Postman ingestion: schema-aware auth,
  body/variable fuzzing, and API-specific abuse cases.
- **White-box mode** — optional source-aware pass (secret scan + SAST) to prioritise
  dynamic testing; also unlocks PR diff-scope.
- Logout/session-invalidation confirmation; race conditions; broader CORS checks.

## Development
```bash
pip install -e ".[dev]"
ruff check . && pytest
```

## License
MIT © saurabh-bhagat-stack — see [LICENSE](LICENSE).
