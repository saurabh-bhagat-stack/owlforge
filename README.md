# owlforge

A **local-first, autonomous agentic penetration-testing platform**.

Original work. Inspired by the best ideas across the field (Strix, XBOW, Shannon,
XalgoriX, and others) but re-expressed as its own architecture, engine, and logic —
not a fork of any of them.

## Design goals
- **Local-first:** drive the whole thing with a local LLM (any OpenAI-compatible
  endpoint — Jan / Ollama / LM Studio / llama.cpp). Hosted models optional, only
  for benchmarking.
- **Isolated execution:** every mission's tooling runs in our own disposable
  sandbox container, talking to the engine over a real protocol (structured,
  streaming, two-way) — not stdout scraping.
- **Autonomous but auditable:** an orchestrator + specialized agents that plan,
  test, validate with proof, and report — with full evidence trails.

## Status
🚧 Rebuild in progress — designing from scratch. See [`docs/`](docs/).
The previous Strix-port prototype lives in the private `owlforge-legacy` repo as a
reference / parts-donor.

## License
MIT © saurabh-bhagat-stack
