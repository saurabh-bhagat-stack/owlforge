---
name: React
applies_to: react
description: React SPA testing notes.
---
## Signals
`react`/`react-dom` scripts, a root `<div id=root>`, client-rendered content.

## Focus
- The real attack surface is built client-side: drive the app in a browser and capture XHR/
  fetch to recover API endpoints and params that static crawling misses.
- DOM XSS: `dangerouslySetInnerHTML`, `href={userInput}` (`javascript:`), ref-based innerHTML.
- Client-side routing hides authz on the API — test the API endpoints directly, unauthenticated.
- Secrets/endpoints embedded in JS bundles; source maps if exposed.
