---
name: CORS misconfiguration
applies_to: cors
description: Cross-origin resource sharing that trusts attacker origins.
---
## Where to look
JSON/API endpoints, anything that sets `Access-Control-Allow-Origin`. Send requests with an
`Origin:` header you control and read the CORS response headers.

## Techniques
- Reflection: `Origin: https://evil.test` echoed back in `Access-Control-Allow-Origin` is a
  misconfiguration. With `Access-Control-Allow-Credentials: true` it is fully exploitable
  (any site reads the victim's authenticated responses).
- `null` origin: allowed `null` is reachable from a sandboxed iframe / `data:` document.
- Trust-boundary tricks: does it allowlist by `startswith`/`endswith`/substring? Try
  `https://trusted.evil.test`, `https://evil-trusted.test`, `https://trusted.test.evil.test`.
- `*` alone is NOT a finding (browsers block `*` + credentials); only reflection/null/weak
  allowlisting is.

## Validation signal
The exact attacker Origin (or `null`) appears in `Access-Control-Allow-Origin`; note whether
`Access-Control-Allow-Credentials: true` accompanies it (raises severity).
