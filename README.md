# owlforge

A **local-first, model-agnostic, autonomous web-application penetration-testing
platform**. Point it at an authorized target and a model you choose drives the whole
assessment — recon → understanding → authentication → planning → multi-agent testing →
evidence-gated validation → report — with all tooling running inside an isolated sandbox
container you build yourself.

Original work — its own architecture and engine, built from the ground up.

> ⚠️ **Status: active development.** The engine works end to end on real targets;
> interfaces and schema still change. **Only test systems you are authorized to assess.**

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
- **Recon is deterministic.** A crawler + ffuf content-discovery + JS/param extraction +
  fingerprint map the surface. For JS-heavy SPAs it adds **browser-driven interactive
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

Vuln classes: SQLi · reflected/DOM/stored XSS · access-control (IDOR + horizontal/vertical
privesc) · path-traversal · SSRF · open-redirect · CRLF · CSRF · SSTI · RCE · NoSQL · XXE ·
deserialization · file-upload · GraphQL · info-disclosure · WebSocket · request-smuggling.

See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) (plan of record), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
and [`docs/recon-spec.md`](docs/recon-spec.md).

## Requirements
- **Python 3.11+**
- **Docker** — for the sandbox (real tool execution). On macOS, [colima](https://github.com/abiosoft/colima) works well.
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

# 4. start Docker, then build the sandbox image (first build pulls the base + tools)
colima start                     # macOS; or ensure Docker Desktop/daemon is running
owlforge sandbox build
owlforge sandbox status          # confirm: docker available + image built
```

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
```bash
# default: multi-agent (recon → plan → specialists → validate → report)
owlforge run -t https://target.example -m "Assess this app for exploitable web vulns"

# give it a project name to group runs
owlforge run -t https://target.example --project acme -m "Full assessment"

# single-agent instead of orchestrated
owlforge run --single -t https://target.example -m "..."

# SPA / JS-heavy app: interactive browser recon (auto-enables when a SPA is detected;
# this forces it on)
owlforge run --browser-recon -t https://app.example -m "..."

# authenticated — pick one (or pass --identities for multi-role / privesc testing)
owlforge run -t https://app.example --auth-cookie "session=..." -m "..."
owlforge run -t https://app.example --auth-header "Authorization: Bearer ..." -m "..."
owlforge run -t https://app.example --login-url https://app.example/login \
             --login-data "username=u&password=p" --login-success "Dashboard" -m "..."
owlforge run -t https://app.example --identities identities.yaml -m "..."

# scope control
owlforge run -t https://app.example --scope api.example --out-of-scope "*/logout*" -m "..."
owlforge run -t https://app.example --only xss,sqli -m "..."          # restrict classes

# extra signal sources (slower, opt-in)
owlforge run -t https://target.example --nuclei -m "..."              # nuclei templates
owlforge run -t https://target.example --deepen -m "..."              # read-only proof escalation
owlforge run -t https://target.example --network-recon -m "..."       # nmap
```

## Review results
```bash
owlforge assessments list          # past assessments
owlforge assessments show <id>
owlforge findings <id>             # findings for an assessment
owlforge report <id>               # markdown report (--rebuild to regenerate)
owlforge report <id> --format html # also HTML + SARIF; md|html|sarif|all
owlforge sandbox status            # docker + image state
```

Useful flags: `--model <id>` (override per run), `--max-turns N`, `--recon/--no-recon`,
`--recon-pages N`, `--no-sandbox` (host-only fallback). The report and findings are also
written under the assessment's workspace directory.

## Honest limitations (today)
- Local ≤27B models **confirm/validate reliably**; fully-autonomous **discovery** is less
  reliable than a frontier model — the deterministic recon + pre-probe + auto-file layer
  is what makes weak models productive. Stronger model = broader coverage, same pipeline.
- Request-smuggling is **detection-only** (low-confidence candidate; no exploitation).
- Reports export to **Markdown, HTML, and SARIF 2.1.0** (CWE/OWASP-tagged for CI).
- Out of scope by design: non-web surfaces (thick-client/mobile/gRPC/SOAP), and any
  destructive action — proof is always read-only (e.g. RCE proven with `id`/`hostname`).

## Development
```bash
pip install -e ".[dev]"
ruff check . && pytest
```

## License
MIT © saurabh-bhagat-stack — see [LICENSE](LICENSE).
