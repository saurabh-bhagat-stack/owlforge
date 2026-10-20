"""Export an assessment's findings to HTML and SARIF 2.1.0.

CWE / OWASP tags are DERIVED from each finding's class (title keywords) at render
time — a mapping, not a coverage claim (owlforge is a web-app vuln finder, not an
ATT&CK red-team). No schema columns are added.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime

from sqlmodel import select

from owlforge.config import assessments_dir
from owlforge.store.db import session
from owlforge.store.models import Assessment, Finding

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# severity -> SARIF level
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}

# (keyword(s) in lowercased title) -> (class_id, CWE, OWASP-2021)
_CLASSMAP: list[tuple[tuple[str, ...], str, str, str]] = [
    (("sql injection", "sqli", "sql-injection"), "sql-injection", "CWE-89", "A03:2021-Injection"),
    (("command injection", "os command", "rce", "remote code"), "command-injection", "CWE-78", "A03:2021-Injection"),
    (("server-side template", "ssti", "template injection"), "ssti", "CWE-1336", "A03:2021-Injection"),
    (("nosql",), "nosql-injection", "CWE-943", "A03:2021-Injection"),
    (("crlf", "header injection", "response splitting"), "crlf", "CWE-93", "A03:2021-Injection"),
    (("cross-site scripting", "xss"), "xss", "CWE-79", "A03:2021-Injection"),
    (("path traversal", "lfi", "local file", "directory traversal"),
     "path-traversal", "CWE-22", "A01:2021-Broken Access Control"),
    (("ssrf", "server-side request"), "ssrf", "CWE-918", "A10:2021-Server-Side Request Forgery"),
    (("open redirect",), "open-redirect", "CWE-601", "A01:2021-Broken Access Control"),
    (("csrf", "cross-site request"), "csrf", "CWE-352", "A01:2021-Broken Access Control"),
    (("idor", "insecure direct object", "access control", "privesc",
      "privilege escalation", "bola"),
     "broken-access-control", "CWE-639", "A01:2021-Broken Access Control"),
    (("xxe", "xml external"), "xxe", "CWE-611", "A05:2021-Security Misconfiguration"),
    (("deserializ",), "insecure-deserialization", "CWE-502",
     "A08:2021-Software and Data Integrity Failures"),
    (("file upload", "webshell", "unrestricted upload"),
     "file-upload", "CWE-434", "A04:2021-Insecure Design"),
    (("graphql",), "graphql", "CWE-200", "A05:2021-Security Misconfiguration"),
    (("request smuggling", "smuggl"), "request-smuggling", "CWE-444",
     "A05:2021-Security Misconfiguration"),
    (("websocket",), "websocket", "CWE-346", "A05:2021-Security Misconfiguration"),
    (("secret", "api key", "token", "credential", "jwt", "password"),
     "info-disclosure", "CWE-200", "A02:2021-Cryptographic Failures"),
    (("csp", "hsts", "x-content-type", "clickjack", "cookie", "cors", "security header",
      "directory listing", "verbose error", "stack trace", "version disclosure",
      "host header"), "misconfiguration", "CWE-16", "A05:2021-Security Misconfiguration"),
]


def classify_finding(f: Finding) -> tuple[str, str, str]:
    """Return (class_id, cwe, owasp) derived from the finding title. Best-effort."""
    t = (f.title or "").lower()
    for keys, cid, cwe, owasp in _CLASSMAP:
        if any(k in t for k in keys):
            return cid, cwe, owasp
    return "other", "CWE-0", ""


def _findings(assessment_id: str):
    with session() as s:
        a = s.get(Assessment, assessment_id)
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
        rows = sorted(rows, key=lambda f: _SEV_ORDER.get(f.severity, 9))
        target = a.target if a else assessment_id
        mode = a.scan_mode if a else ""
        # detach: pull plain dicts so we can use them after the session closes
        data = [{
            "id": f.id, "title": f.title, "severity": f.severity, "status": f.status,
            "confidence": f.confidence, "endpoint": f.endpoint or "", "method": f.method or "GET",
            "analysis": f.technical_analysis or "", "poc": f.proof_of_concept or "",
            "repro": f.repro_command or "", "impact": f.impact or "",
            "remediation": f.remediation or "", "note": f.validation_note or "",
            "class": classify_finding(f),
        } for f in rows]
    return target, mode, data


def _write(assessment_id: str, name: str, content: str) -> str | None:
    try:
        d = assessments_dir() / assessment_id
        d.mkdir(parents=True, exist_ok=True)
        fp = d / name
        fp.write_text(content, encoding="utf-8")
        return str(fp)
    except Exception:
        return None


# ---------------------------------------------------------------- SARIF ------

def to_sarif(assessment_id: str) -> tuple[dict, str | None]:
    """Build a SARIF 2.1.0 log (one rule per vuln class, results per finding).
    Only validated/reported findings become results; candidates are omitted
    (SARIF consumers treat results as confirmed)."""
    target, _mode, data = _findings(assessment_id)
    validated = [d for d in data if d["status"] in ("validated", "reported")]

    rules: dict[str, dict] = {}
    results: list[dict] = []
    for d in validated:
        cid, cwe, owasp = d["class"]
        if cid not in rules:
            tags = [t for t in (cwe, owasp) if t and t != "CWE-0"]
            rules[cid] = {
                "id": cid,
                "name": cid.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": d["title"]},
                "properties": {"tags": tags, "cwe": cwe, "owasp": owasp,
                               "security-severity": {"critical": "9.5", "high": "8.0",
                                                     "medium": "5.0", "low": "3.0",
                                                     "info": "1.0"}.get(d["severity"], "5.0")},
            }
        loc = d["endpoint"] or target
        results.append({
            "ruleId": cid,
            "level": _SARIF_LEVEL.get(d["severity"], "warning"),
            "message": {"text": f"{d['title']} — {d['note'] or d['impact'] or 'validated'}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": loc}}}],
            "properties": {"severity": d["severity"], "confidence": d["confidence"],
                           "method": d["method"]},
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "owlforge",
                "informationUri": "https://github.com/saurabh-bhagat-stack/owlforge",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": target,
                           "generatedAt": datetime.now(UTC).isoformat()},
        }],
    }
    path = _write(assessment_id, "report.sarif.json", json.dumps(sarif, indent=2) + "\n")
    return sarif, path


# ----------------------------------------------------------------- HTML ------

_SEV_COLOR = {"critical": "#b3123a", "high": "#d2461e", "medium": "#c08a00",
              "low": "#2b7a9b", "info": "#5a6b7b"}


def _esc(s: str) -> str:
    return html.escape(s or "")


def _html_finding(d: dict) -> str:
    cid, cwe, owasp = d["class"]
    color = _SEV_COLOR.get(d["severity"], "#5a6b7b")
    tags = " ".join(
        f'<span class="tag">{_esc(x)}</span>'
        for x in (cwe if cwe != "CWE-0" else "", owasp) if x
    )
    parts = [
        '<section class="finding">',
        (f'<h3><span class="badge" style="background:{color}">'
         f'{_esc(d["severity"].upper())}</span> {_esc(d["title"])}</h3>'),
        f'<div class="meta">status: {_esc(d["status"])} · confidence: {_esc(d["confidence"])} {tags}</div>',
    ]
    if d["endpoint"]:
        parts.append(f'<div class="meta">endpoint: <code>{_esc(d["method"])} {_esc(d["endpoint"])}</code></div>')
    if d["note"]:
        parts.append(f'<p><strong>Validation:</strong> {_esc(d["note"])}</p>')
    if d["analysis"]:
        parts.append(f'<p><strong>Analysis.</strong> {_esc(d["analysis"])}</p>')
    for label, key in (("Proof of concept", "poc"), ("Reproduction", "repro")):
        if d[key]:
            parts.append(f'<p><strong>{label}</strong></p><pre>{_esc(d[key])}</pre>')
    if d["impact"]:
        parts.append(f'<p><strong>Impact.</strong> {_esc(d["impact"])}</p>')
    if d["remediation"]:
        parts.append(f'<p><strong>Remediation.</strong> {_esc(d["remediation"])}</p>')
    parts.append("</section>")
    return "\n".join(parts)


def to_html(assessment_id: str) -> tuple[str, str | None]:
    target, mode, data = _findings(assessment_id)
    validated = [d for d in data if d["status"] in ("validated", "reported")]
    candidates = [d for d in data if d["status"] == "candidate"]
    rejected = [d for d in data if d["status"] == "false_positive"]
    sev = {k: sum(1 for d in validated if d["severity"] == k) for k in _SEV_ORDER}
    risk = next((k.capitalize() for k in _SEV_ORDER if sev[k] > 0), "Informational")

    cand_rows = "".join(
        f'<li><span class="badge sm" style="background:{_SEV_COLOR.get(d["severity"], "#5a6b7b")}">'
        f'{_esc(d["severity"].upper())}</span> {_esc(d["title"])}'
        + (f' — <em>{_esc(d["note"])}</em>' if d["note"] else "") + "</li>"
        for d in candidates
    )
    body = "\n".join(_html_finding(d) for d in validated) or \
        "<p><em>None validated with a reproducible proof-of-concept.</em></p>"

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>owlforge report — {_esc(target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.6 -apple-system, system-ui, sans-serif; max-width: 920px;
         margin: 0 auto; padding: 24px 16px; color: #1a1a1a; background: #fff; }}
  @media (prefers-color-scheme: dark) {{ body {{ color: #e6e6e6; background: #15171a; }}
    code, pre {{ background: #22262b !important; }} .finding {{ border-color:#333 !important; }}
    .tag {{ background:#22262b !important; border-color:#333 !important; }} }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }} h3 {{ margin: 0 0 6px; font-size: 17px; }}
  .sub {{ color: #777; margin: 0 0 20px; }}
  .badge {{ color:#fff; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; }}
  .badge.sm {{ font-size: 11px; }}
  .finding {{ border: 1px solid #e2e2e2; border-radius: 8px; padding: 14px 16px; margin: 14px 0; }}
  .meta {{ color: #777; font-size: 13px; margin-bottom: 6px; }}
  .tag {{ display:inline-block; border:1px solid #ddd; background:#f6f6f6; border-radius:4px;
         padding:0 6px; font-size:11px; margin-left:4px; color:inherit; }}
  code {{ background:#f4f4f4; padding:1px 5px; border-radius:4px; }}
  pre {{ background:#f4f4f4; padding:10px 12px; border-radius:6px; overflow:auto; font-size:13px; }}
  .counts span {{ margin-right: 14px; font-weight:600; }}
</style></head><body>
<h1>owlforge assessment — {_esc(target)}</h1>
<p class="sub">scan mode: {_esc(mode)} · overall risk: <strong>{risk}</strong> ·
 generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}</p>
<p class="counts">
 <span>Validated: {len(validated)}</span>
 <span>Candidates: {len(candidates)}</span>
 <span>Rejected: {len(rejected)}</span></p>
<p class="counts">
 <span style="color:{_SEV_COLOR['critical']}">{sev['critical']} critical</span>
 <span style="color:{_SEV_COLOR['high']}">{sev['high']} high</span>
 <span style="color:{_SEV_COLOR['medium']}">{sev['medium']} medium</span>
 <span style="color:{_SEV_COLOR['low']}">{sev['low']} low</span></p>
<h2>Validated findings</h2>
{body}
{('<h2>Candidates (need manual validation)</h2><ul>' + cand_rows + '</ul>') if candidates else ''}
</body></html>
"""
    path = _write(assessment_id, "report.html", page)
    return page, path
