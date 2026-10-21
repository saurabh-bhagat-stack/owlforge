---
name: SQL injection
applies_to: sqli
description: Confirming and escalating SQL injection without destructive actions.
---
## Where to look
Numeric/string params feeding WHERE/ORDER BY/LIMIT, search, filters, `id`/`sort`/`category`,
JSON body fields, and headers reflected into queries. Test GET **and** POST bodies.

## Techniques
- Error-based: a single quote `'` that breaks the query (500/SQL error) and a balanced `''`
  that restores 200 is a strong signal. Try `)` and `"` too for different contexts.
- Boolean-based: `' AND 1=1-- -` vs `' AND 1=2-- -` producing different responses.
- ORDER BY probing to find column count, then UNION SELECT for in-band read.
- Different contexts need different breakouts: numeric (no quote), single-quote string,
  double-quote, LIKE `%`, IN(...), ORDER BY.

## Bypasses
Inline comments `/**/`, case variation, `%27`/double-encoding, `UNION/*!50000SELECT*/`,
whitespace alternatives (`%0a`,`/**/`), when a WAF filters keywords.

## Validation signal
500-on-`'` then 200-on-`''`; a boolean pair that flips content; or a UNION value echoed.
Keep proof read-only: extract version/current_user only — never write or drop.

## Example payloads
`1'` · `1''` · `1' AND 1=1-- -` · `1' AND 1=2-- -` · `1) OR ('1'='1` · `1 ORDER BY 5-- -`
