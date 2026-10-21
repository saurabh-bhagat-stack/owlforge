---
name: XML external entity (XXE)
applies_to: xxe
description: External entity injection in XML/SOAP/SVG/office endpoints.
---
## Where to look
Anything parsing XML: `Content-Type: application/xml`/`text/xml`, SOAP, SVG upload, DOCX/XLSX,
RSS, SAML, and 'stock check'/import endpoints that take an XML body.

## Techniques
- In-band file read: define a DOCTYPE with an external entity pointing at `file:///etc/passwd`
  and reference it in a value echoed back.
- Blind/OOB: entity points at your collaborator (`http://oob/`) or use a parameter entity +
  external DTD to exfiltrate; confirm by the callback.
- Try replacing JSON with XML on endpoints that accept both.

## Validation signal
File contents echoed (e.g. `root:x:0:0`) OR an OOB callback with the exfiltrated data.

## Example payload
`<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><stock><productId>&x;</productId></stock>`
