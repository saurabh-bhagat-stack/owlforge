---
name: Cross-site scripting
applies_to: xss
description: Reflected/stored/DOM XSS — confirm execution, not mere reflection.
---
## Where to look
Any param reflected into HTML. Note the CONTEXT: HTML body, attribute (`"`), JS string
(`'`/`"`/`</script>`), URL, or a framework template. DOM sinks: innerHTML, document.write,
`location`, `eval`, jQuery `.html()`.

## Techniques
- Reflect a unique marker first; check if it is HTML-encoded (`&lt;`) or raw.
- Break out of the exact context: body `<svg onload=...>`; attribute `"><img src=x
  onerror=...>`; JS string `';alert(1)//` or `</script><img ...>`.
- Stored: submit via one endpoint, re-fetch the page that renders it.

## Bypasses
`onerror`/`onload`/`onfocus autofocus`; `<svg>`,`<math>`; `javascript:` in href; mixed case;
HTML entities; when `<`/`>` filtered try attribute/event-handler injection only.

## Validation signal
REAL browser execution (a JS side effect fires), not reflection. If quotes AND `/` are
escaped in a JS-string sink, it may NOT be exploitable — move to another param/context.

## Example payloads
`"><img src=x onerror=alert(1)>` · `<svg onload=alert(1)>` · `';alert(1)//` · `javascript:alert(1)`
