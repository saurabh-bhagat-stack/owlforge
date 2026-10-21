---
name: Server-side template injection
applies_to: ssti
description: Template injection → escalate to file read / code exec.
---
## Where to look
Values rendered through a template engine: name/greeting/subject fields, error pages,
email/PDF templates, and anywhere user input appears in server-rendered output.

## Techniques
- Detect with a math probe unique enough to avoid coincidence: `{{1337*1337}}` → 1787569
  (Jinja2/Twig), `${1337*1337}` (FreeMarker/JSP EL), `#{1337*1337}` (Ruby), `<%=1337*1337%>`.
- Identify the engine from which probe evaluates, then escalate to object/`config` access,
  file read, or OS command via that engine's gadgets.

## Validation signal
The arithmetic is evaluated server-side (1787569 appears). Escalate read-only.

## Example payloads
`{{1337*1337}}` · `${1337*1337}` · `#{1337*1337}` · `{{7*'7'}}` (engine fingerprint)
