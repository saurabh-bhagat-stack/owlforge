---
name: Path traversal / LFI
applies_to: path_traversal
description: Directory traversal and local file inclusion.
---
## Where to look
File/path params: `file=`,`path=`,`page=`,`template=`,`download=`,`lang=`,`include=`, and
any value that becomes a filesystem path or an include.

## Techniques
- `../../../../etc/passwd` and Windows `..\..\win.ini`; try absolute paths.
- Bypasses: URL-encode (`%2e%2e%2f`), double-encode, `....//`, null byte `%00` (legacy),
  strip-and-rejoin tricks, and a known path prefix the app expects + traversal.
- LFI → RCE: log poisoning, PHP wrappers (`php://filter`,`data://`), session files.

## Validation signal
Known file contents returned (`root:x:0:0:` for /etc/passwd, `[extensions]` for win.ini).

## Example payloads
`../../../../etc/passwd` · `..%2f..%2f..%2fetc%2fpasswd` · `....//....//etc/passwd`
