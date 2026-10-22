# Contributing to owlforge

Thanks for your interest. owlforge is a local-first, model-agnostic, autonomous web-app
pentesting platform; contributions that keep it **sound and evidence-gated** are welcome.

## Development setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && pytest        # both must pass before a PR
```

## Ground rules
- **No false positives.** A finding is only `validated` when owlforge reproduces its proof.
  New detection must be deterministic or evidence-gated; candidate-level is fine when a
  claim cannot be soundly auto-confirmed — label it as such.
- **Non-destructive.** Proof is read-only. Never add code that writes, deletes, or degrades
  a target to "prove" an issue.
- **Generic, not target-specific.** No hardcoded hostnames, credentials, or lab-specific
  logic. It must work against any authorized target.
- **Tests + lint.** Add tests for new behavior; keep `ruff check .` clean.

## Adding a knowledge pack
Drop a markdown file under `owlforge/knowledge/<category>/<name>.md` with YAML frontmatter
(`name`, `applies_to`, `description`) and a methodology body. It is injected into the
matching specialist automatically.

## Pull requests
Keep PRs focused, describe the change and how you verified it, and ensure CI is green.
