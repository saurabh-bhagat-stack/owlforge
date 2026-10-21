---
name: SSRF / open redirect
applies_to: ssrf_redirect
description: Distinguish a server-side fetch (SSRF) from a mere off-site redirect (open redirect).
---
## Where to look
URL/host/path params: `url=`,`next=`,`redirect=`,`callback=`,`image=`,`webhook=`,`feed=`,
`proxy=`, and any 'fetch this for me' feature (previews, imports, PDF/screenshot renderers).

## Techniques
- OPEN REDIRECT: the supplied URL lands in the 3xx `Location` header → the browser would go
  off-site. Medium severity (CWE-601). NOT SSRF.
- SSRF: the SERVER fetches the URL. Prove via out-of-band callback (a request arrives at your
  collaborator) OR fetched content appearing in the response. Try internal targets:
  `http://169.254.169.254/latest/meta-data/`, `http://127.0.0.1:port`, `http://[::1]`.
- Bypasses: alternate IP encodings (decimal/octal/IPv6), `@`-tricks, DNS rebinding, redirect
  from an attacker host to an internal one.

## Validation signal
SSRF = an OOB callback fires or internal content is reflected. Open redirect = attacker host
in Location. Do not label a reflected URL in the body as SSRF (no proof of a fetch).
