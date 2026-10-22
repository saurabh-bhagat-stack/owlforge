---
name: Unrestricted file upload
applies_to: file_upload
description: Uploading server-executable or dangerous files to reach RCE.
---
## Where to look
Any upload: avatar/profile image, document/CSV import, attachments, logo, import/export,
rich-text image paste. Note the upload endpoint, the field name, and where the file is
served back from.

## Techniques
- Upload a benign MARKER file first and fetch it back to learn the storage path/URL scheme.
- Try a server-executable extension matching the stack: `.php .php5 .phtml` (PHP),
  `.jsp .jspx` (Java), `.asp .aspx` (IIS), `.svg` (stored XSS), `.html`.
- Bypass filters: double extension `shell.php.jpg`, case `.PhP`, trailing dot/space/null,
  `Content-Type` spoofing (image/png with script body), magic-byte prefix (GIF89a; then code),
  path traversal in the filename to control where it lands.
- For RCE proof keep it READ-ONLY: a script that echoes a unique marker (or runs `id`), fetch
  it, and confirm the marker/`uid=` appears — do not deface or persist a real shell.

## Validation signal
The uploaded file is served AND executes (your marker/`id` output comes back), or an SVG/HTML
upload executes script when viewed.
