---
name: Next.js
applies_to: nextjs
description: Next.js-specific weak spots.
---
## Signals
`/_next/` assets, `__NEXT_DATA__` JSON in HTML, `x-nextjs-*` headers, React hydration.

## Focus
- API routes under `/api/*` — test each for authz/IDOR/injection independently of the UI.
- `__NEXT_DATA__` and build manifests leak routes, props, and sometimes secrets/API endpoints.
- SSRF/open-redirect in image optimizer (`/_next/image?url=`).
- Middleware authz bypass (header/path tricks); server actions accepting unexpected input.
- Client-side nav means real surface is in the JS bundles — mine them for endpoints/params.
