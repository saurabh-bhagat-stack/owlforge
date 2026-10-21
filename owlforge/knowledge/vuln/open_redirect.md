---
name: Open redirect
applies_to: open_redirect
description: Off-site redirect via a user-controlled destination.
---
## Where to look
`next`,`redirect`,`url`,`return`,`returnUrl`,`callback`,`dest`,`continue` — login/logout flows,
OAuth `redirect_uri`, post-action landing.

## Techniques
- Set the param to an external origin; a 3xx with `Location: https://attacker/` confirms it.
- Bypass naive allowlists: `//attacker`, `https:attacker`, `/\attacker`, `?url=@attacker`,
  `attacker#trusted`, trusted-host-as-subdomain, backslashes, double-encoding.

## Validation signal
The response `Location` points to an attacker-controlled off-site origin. Medium (CWE-601).
Pair with OAuth to assess token leakage via `redirect_uri`.
