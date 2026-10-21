---
name: Express / Node
applies_to: express
description: Express/Node.js weak spots.
---
## Signals
`X-Powered-By: Express`, `connect.sid` cookie, JSON APIs, `/api/`.

## Focus
- Prototype pollution via merged query/body (`__proto__`,`constructor.prototype`) → check libs
  like lodash merge; can escalate to RCE/authz bypass.
- NoSQL injection (Mongo) in login/search with object operators.
- SSRF in URL-fetching endpoints; command injection via `child_process` wrappers.
- Missing `helmet` headers; JWT with `alg:none` or weak secret.
- Path traversal in static file serving / `res.sendFile(userInput)`.
