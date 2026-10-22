# owlforge — Usage

Install and first-run setup is in the [README](../README.md). This guide is worked
examples for real assessments. **Only test targets you are authorized to assess.**

## The one command

```bash
owlforge run <target>
```

A bare host is fine (`https://` is assumed). It runs **deep by default** — recon +
interactive SPA mapping, understanding (secrets/JS→API), authentication, deterministic
pre-probe, specialist agents, out-of-band (blind) testing, access-control and auth-logic
checks, validation, and a report — all automatic. Each run gets an auto project name
`<host>-<hash>` so repeat scans of the same target stay separate.

```bash
owlforge run ginandjuice.shop
```

### Point it at an API description

Give it an OpenAPI/Swagger file (JSON or YAML) or a Postman collection and owlforge
derives the base URL and tests every operation — no crawling needed. Specs served by
the target are also auto-discovered during recon.

```bash
owlforge run ./openapi.yaml            # OpenAPI 3 / Swagger 2 (json or yaml)
owlforge run ./postman_collection.json # Postman v2.x collection
```

## Steering it with `-m`

`-m/--message` is optional, free-text, and the highest-priority guidance; it reaches the
specialists. Put scope, credentials, focus areas, constraints there:

```bash
owlforge run app.example -m "In scope: app.example + api.example. Out of scope: */billing/*.
Focus on IDOR and SSRF in the checkout flow. Rate-limit to 5 req/s.
Creds: alice/Passw0rd! (user), admin bob/hunter2 (admin)."
```

## Authenticated & multi-user (IDOR / privilege escalation)

Horizontal IDOR/BOLA needs **two real user accounts**; vertical privesc needs a lower- and
higher-privilege pair. Provide them in a YAML file (schema + examples in
[`examples/identities.yaml`](../examples/identities.yaml)):

```bash
owlforge run app.example --identities examples/identities.yaml
```

owlforge logs each identity in, re-maps the authenticated surface (including an interactive
browser pass), then runs a sound owner/other-identity/anonymous **differential** over
object and account endpoints:

- a different authenticated identity reading the owner's protected resource → **IDOR / BOLA**
  (or **vertical privilege escalation** if its role is lower);
- an account-scoped resource readable anonymously → **missing authentication**;
- a public page (anon sees the same content) is **never** flagged — no false positives.

A single session (e.g. a harvested login) still catches anon-readable account pages, but
cross-user IDOR needs the second account.

## Out-of-band testing (blind SSRF / XXE) — `[oast]`

Blind vulnerabilities are proved by a callback to a host owlforge controls. It tries, in
order: **public interactsh** (self-tested — skipped if the server can't decrypt), a
**cloudflared/ngrok tunnel** to an in-sandbox listener, then your **own collaborator**.
If none is reachable (e.g. your org blocks them), it flags suspected sinks as
*needs manual verification* and tells you which key to set. Configure in
`~/.owlforge/config.toml`:

```toml
[oast]
enabled = true
server = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"  # public interactsh
tunnel = true            # cloudflared quick-tunnel if interactsh is blocked
ngrok_token = ""         # use ngrok instead of cloudflared (needs an authtoken)
collaborator_url = ""    # your self-hosted interactsh / collaborator domain
token = ""               # if that server is auth-protected
```

On a locked-down corporate network, set `collaborator_url` (and `token`) to a self-hosted
interactsh domain you control.

## Scope, model, nmap

```bash
owlforge run app.example --scope api.example --out-of-scope "*/logout*"  # enforced boundary
owlforge run app.example --model saluki-27b:latest                       # per-run model override
owlforge run app.example --network-recon                                 # also nmap (opt-in)
```

## Reading results

```bash
owlforge assessments list              # past runs (auto-named <host>-<hash>)
owlforge findings <assessment_id>      # table of findings
owlforge report  <assessment_id>                 # Markdown (CVSS per finding)
owlforge report  <assessment_id> --format all    # also report.html + report.sarif.json
owlforge diff    <assessment_id>                 # NEW / FIXED / PERSISTING vs the previous run
```

Reports and raw evidence are written under `~/.owlforge/assessments/<id>/`. Every validated
finding carries a CVSS 3.1 score + vector and is tagged with CWE + OWASP; the SARIF export
drops straight into CI code-scanning.

## What runs, in order

`recon (unauth → auto-escalate to auth, interactive SPA map, katana, ffuf, nuclei, WAF) →
understand (secrets / JS→API) → plan (classify + deterministic pre-probe that auto-files
confirmed findings) → specialists (SQLi/XSS/SSRF/SSTI/RCE/path/XXE/… with a bypass loop) →
out-of-band (blind SSRF/XXE) → access-control (IDOR/privesc/missing-authn) → auth-logic
(JWT alg=none + weak secret) → business-logic (candidate probes) → validate (evidence-gated;
XSS by real browser execution) → collapse + dedupe → exploit-chaining → report.`

Everything that files a finding is evidence-gated or deterministically confirmed; proof is
read-only (e.g. RCE shown with `id`/`hostname`) — owlforge never performs a destructive
action.
