# Phase 4 — Multi-agent: the Recon agent (+ auth)

> _Design reference. owlforge is built to this spec; where the shipped code has
> moved on, [ARCHITECTURE.md](ARCHITECTURE.md) and the source are authoritative._


## Why
Benchmarks showed local models *confirm* vulns reliably when guided but *discover*
them unreliably — they under-enumerate the attack surface. The fix is not more prompt
text; it is a **recon agent** that builds an explicit, deterministic **attack-surface
inventory**, which the testing agent then works through parameter-by-parameter.

## Shape (two-phase orchestration)
```
Orchestrator
  ├─ Phase A: RECON agent  → produces Attack Surface Inventory (endpoints/params/forms)
  └─ Phase B: TESTING agent → receives the inventory; tests each item per playbook
```
Recon reliability comes from a deterministic `map_surface` crawl tool (parse links,
forms, query params), not from the model remembering to enumerate. The recon agent
drives the crawl (seeds, depth, which areas) and records anything the crawler misses.

## Auth model — recon runs UNAUTHENTICATED **and** AUTHENTICATED
Authenticated recon exposes a different, usually larger surface (account, admin,
API). owlforge supports three auth modes, resolved ONCE into a set of session headers
that every sandbox HTTP request then carries:

- **unauth** (default): no credentials; map the public surface.
- **session**: operator supplies a ready session directly — a `Cookie` and/or
  `Authorization`/custom header (they logged in themselves). Most robust.
- **login**: operator supplies a login URL + form fields (incl. credentials) + a
  success signal; owlforge performs a form login, captures `Set-Cookie`, and uses it.
  (Form POST is built in the engine as a urlencoded body — no new sandbox endpoint.)

Credentials are operator-provided for an authorized target (the operator's own /
authorized app) and are injected into the sandbox tools, never echoed back. For a
real assessment the inventory should be built in BOTH modes when creds exist: the
delta (authenticated-only endpoints) is itself high-value.

## Pieces
- `engine/auth.py`: `AuthContext` + `establish_session(request_fn) -> headers`.
- `ToolContext.session_headers`: merged into every `http_request` (and curl via
  `exec_command` later).
- `tools`: `map_surface` (deterministic crawl → inventory) + inventory stored per
  assessment; testing agent prompt is seeded with the inventory.
- `engine/orchestrator.py`: recon phase → testing phase, passing the inventory.
- CLI: `--auth-cookie`, `--auth-header`, or `--login-url/--login-data/--login-success`.

## Build order
1. Auth foundation (AuthContext, session header injection) — this commit.
2. `map_surface` crawl tool + inventory store.
3. Recon agent + two-phase orchestrator; CLI auth flags.
4. Re-bench unguided (with recon) to measure the discovery lift.
