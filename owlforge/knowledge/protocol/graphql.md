---
name: GraphQL
applies_to: graphql
description: GraphQL-specific testing: introspection, suggestion, authz, injection.
---
## Where to look
`/graphql`,`/api/graphql`,`/query`,`/gql`. POST with `{"query":"..."}`.

## Techniques
- Introspection: `query{__schema{types{name}}}` — if it returns the schema, the whole API is
  mapped. Even with introspection off, FIELD SUGGESTION ("Did you mean") leaks names.
- Enumerate queries/mutations; test authz per-field (a low-priv user hitting admin mutations).
- Injection reaches resolvers: SQLi/NoSQL/command injection in arguments.
- Batching/aliases to bypass rate limits or brute force; deep/nested queries for DoS (report,
  don't execute destructively).

## Validation signal
Schema returned via introspection; a mutation succeeding without proper authz; an injection
confirmed in a resolver argument.
