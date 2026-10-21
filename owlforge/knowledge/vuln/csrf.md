---
name: Cross-site request forgery
applies_to: csrf
description: State-changing requests that lack anti-CSRF enforcement.
---
## Where to look
State-changing POST/PUT/PATCH/DELETE: change email/password, add-to-cart, transfer, role,
settings. Note the session cookie's SameSite attribute.

## Techniques
- Does the request carry an anti-CSRF token? If so, replay it with the token REMOVED or set
  to a WRONG value (every other field intact). If the server still processes it, the token
  is not enforced → CSRF.
- No token + `SameSite=None`/absent → classically forgeable.
- Check Origin/Referer validation too.

## Validation signal
A request with a missing/corrupted token is processed normally (not rejected). Keep it a
candidate unless you can confirm the action took effect without side-effects.
