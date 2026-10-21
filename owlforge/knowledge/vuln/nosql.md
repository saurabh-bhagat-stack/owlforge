---
name: NoSQL injection
applies_to: nosql
description: Operator injection against document stores (e.g. Mongo).
---
## Where to look
Login and search against NoSQL backends; JSON bodies where a string field could become an
object; query params parsed into objects.

## Techniques
- Operator injection: `{"username":{"$ne":null},"password":{"$ne":null}}` to bypass auth;
  `[$gt]=`/`[$ne]=` in form/query encodings.
- JS injection: `'||'1'=='1` in `$where`-style contexts.
- Blind boolean with `$regex` to extract values.

## Validation signal
Operator payloads change auth/query behaviour (login success, differing result sets) in a way
a literal string cannot.
