# owlforge

A **local-first, autonomous, agentic penetration-testing platform**. Point it at a
target, and a local LLM drives recon → multi-agent testing → evidence-gated validation
→ a report, with all tooling running inside an isolated sandbox container.

Original work — inspired by the best ideas across the field (Strix, XBOW, et al.) but
its own architecture and engine.

> ⚠️ **Status: active early development.** The engine works end to end; interfaces and
> schema still change. Only test systems you are authorized to assess.

## Why local-first
owlforge is built to be driven by a **local** model (any OpenAI-compatible endpoint:
Ollama / Jan / LM Studio / llama.cpp). Designing for a modest local model forces a
robust, model-agnostic harness — which then runs even better on a frontier model. Hosted
models work too (via the same OpenAI-compatible client); they're optional.

## How it works
```
recon (deterministic)        →  blackboard        →  orchestrator      →  specialists         →  validation         →  report
crawl + content-discovery       attack-surface        classify params      focused per-class       re-run the PoC         markdown
+ JS + fingerprint              inventory (SQLite)     -> plan tasks        agents (SQLi/XSS/…)     (evidence-gated)
```
- **Recon is deterministic** (a crawler + ffuf content discovery + JS/param extraction) —
  it reliably maps the surface so the LLM doesn't have to remember to enumerate.
- **Orchestrator** classifies each parameter and dispatches **focused specialist agents**.
- **Validation is evidence-gated**: a finding is only `validated` if owlforge re-runs its
  proof-of-concept and the success signal reproduces — not because the model asserted it.
- Runs **unauthenticated or authenticated** (session cookie / header / form login).

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/recon-spec.md`](docs/recon-spec.md).

## Requirements
- Python 3.11+
- Docker (for the sandbox — real tool execution)
- A local OpenAI-compatible LLM server (e.g. Ollama)

## Install
```bash
pip install -e .            # or:  pip install -e ".[dev]"  for tests/lint
owlforge init               # writes ~/.owlforge/config.toml + the local DB
owlforge sandbox build      # builds the owlforge-sandbox image (first build pulls base)
```

## Configure
Edit `~/.owlforge/config.toml` — point it at your model:
```toml
[llm]
base_url = "http://127.0.0.1:11434/v1"   # Ollama's OpenAI-compatible endpoint
model    = "qwen3-14b:40k"               # a model your server actually serves
context_window = 0                        # 0 = auto-detect the model's window
```
> Ollama tip: a bare `hf.co/...` GGUF serves only ~4k context by default. Create a
> Modelfile with `PARAMETER num_ctx <N>` (matching the model's real window) and
> `ollama create`. owlforge auto-detects the served context.

## Use
```bash
# unauthenticated assessment (single agent)
owlforge run -m "Assess https://target.example for exploitable web vulns" -t https://target.example

# multi-agent: recon -> plan -> specialist agents
owlforge run --orchestrate -m "Assess the target" -t https://target.example

# authenticated (pick one)
owlforge run -t https://app.example --auth-cookie "session=..." -m "..."
owlforge run -t https://app.example --auth-header "Authorization: Bearer ..." -m "..."
owlforge run -t https://app.example --login-url https://app.example/login \
             --login-data "username=u&password=p" --login-success "Dashboard" -m "..."

# optional active network recon (nmap) — off by default
owlforge run --network-recon -m "..." -t https://target.example

owlforge assessments list              # past assessments
owlforge assessments show <id>
owlforge findings <id>
owlforge report <id>                   # print the markdown report
owlforge sandbox status                # docker + image state
```
Useful flags: `--model <id>` (override per run), `--max-turns N`, `--recon/--no-recon`,
`--recon-pages N`, `--single` behaviour is the default (omit `--orchestrate`).

## Honest limitations (today)
- Local ≤27B models **confirm/validate reliably when guided to a parameter**, but
  **autonomous discovery is still unreliable** — recon + the orchestrator narrow this gap.
- **Access-control / IDOR** findings are not auto-validated (a single successful request
  isn't proof) — they're kept as candidates pending differential testing.
- JS-heavy SPAs whose links are fully dynamic may need **browser-driven recon** (planned).

## Development
```bash
pip install -e ".[dev]"
ruff check . && pytest
```

## License
MIT © saurabh-bhagat-stack — see [LICENSE](LICENSE).
