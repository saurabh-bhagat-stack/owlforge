---
name: Broken access control / IDOR
applies_to: access_control
description: Horizontal/vertical authz testing with sound differentials.
---
## Where to look
Object ids in path/query/body (`/order/123`, `?userId=`), account pages, admin routes,
function-level actions (export, delete, role change), and mass-assignment of `role`/`isAdmin`.

## Techniques
- Horizontal: as user A, request B's object id. Need TWO accounts to prove it soundly.
- Vertical: as a low-priv user, hit admin-only endpoints/functions.
- Sound differential: owner reads X (200 w/ content); a DIFFERENT identity reading the same
  bytes = broken access control; anon reading the same bytes as everyone = PUBLIC, not a bug.
- Also test method/ää verb tampering and ID formats (int, UUID, hashid).

## Validation signal
A second authenticated identity (or anon) receives another user's private data that the
owner sees, AND a public page returns the same to everyone is explicitly excluded.

## Notes
Without a second account this can only be a candidate — say so. Never mutate others' data
to prove it; read-only confirmation.
