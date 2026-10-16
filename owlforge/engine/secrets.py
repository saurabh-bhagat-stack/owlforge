"""Broad secret / sensitive-information scanner.

Scans text (JS bundles, HTML, inline scripts, comments, JSON, exposed files) for
credentials, keys, tokens and connection strings. Per project policy, matched VALUES
are kept IN FULL — they are the proof of the leak and are surfaced verbatim in
findings and reports (never redacted or truncated).

Two consumers:
  - the Understand pass files each hit as an information-disclosure finding;
  - the auth pipeline turns a usable credential into a session header to escalate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# severity ranking for ordering / de-dup
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Secret:
    kind: str          # e.g. "aws_access_key_id"
    value: str         # the FULL matched secret (proof — never truncated)
    severity: str      # critical | high | medium | low
    context: str       # a short window around the match, for the report


# (kind, severity, compiled pattern, value-group index). Patterns are conservative to
# keep precision high; the value group captures the whole secret.
_PATTERNS: list[tuple[str, str, re.Pattern[str], int]] = [
    ("private_key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 0),
    ("aws_access_key_id", "high", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 1),
    ("aws_secret_access_key", "high",
     re.compile(r"(?i)aws.{0,24}?(?:secret|sk)[\"'\s:=]{1,6}([A-Za-z0-9/+]{40})"), 1),
    ("gcp_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), 1),
    ("github_token", "high", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{36,})\b"), 1),
    ("stripe_live_key", "high", re.compile(r"\b(sk_live_[0-9A-Za-z]{16,})\b"), 1),
    ("stripe_test_key", "medium", re.compile(r"\b(sk_test_[0-9A-Za-z]{16,})\b"), 1),
    ("google_oauth", "high", re.compile(r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"), 1),
    ("db_connection_string", "high",
     re.compile(r"\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://"
                r"[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+)"), 1),
    ("basic_auth_url", "high", re.compile(r"\b(https?://[^/\s:@\"']{1,64}:[^/\s@\"']{1,64}@[^\s\"'<>]+)"), 1),
    ("bearer_token", "medium",
     re.compile(r"(?i)authorization[\"'\s]{0,3}[:=][\"'\s]{0,3}Bearer\s+([A-Za-z0-9._\-]{20,})"), 1),
    ("jwt", "medium", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"), 1),
    ("generic_api_key", "medium",
     re.compile(r"(?i)(?:api[_-]?key|apikey|x-api-key|client[_-]?secret|access[_-]?token|auth[_-]?token)"
                r"[\"'\s]{0,3}[:=][\"'\s]{0,3}[\"']([A-Za-z0-9._\-]{16,})[\"']"), 1),
    ("hardcoded_password", "medium",
     re.compile(r"(?i)(?:password|passwd|pwd)[\"'\s]{0,3}[:=][\"'\s]{0,3}[\"']([^\"'\s]{6,})[\"']"), 1),
]

# noise filters — obvious non-secrets that patterns may catch
_PLACEHOLDERS = ("example", "placeholder", "your_", "xxxx", "<", "changeme", "dummy",
                 "test123", "password", "redacted", "******", "token_here", "insert")


def _looks_placeholder(value: str) -> bool:
    v = value.lower()
    return any(p in v for p in _PLACEHOLDERS) or len(set(value)) <= 3


def scan_text(text: str, *, window: int = 40) -> list[Secret]:
    """Return every distinct secret found in `text`, highest-severity first.
    Values are returned in full (proof); obvious placeholders are skipped."""
    if not text:
        return []
    seen: dict[tuple[str, str], Secret] = {}
    for kind, sev, pat, grp in _PATTERNS:
        for m in pat.finditer(text):
            value = m.group(grp) if grp else m.group(0)
            if not value or _looks_placeholder(value):
                continue
            key = (kind, value)
            if key in seen:
                continue
            start = max(0, m.start() - window)
            end = min(len(text), m.end() + window)
            ctx = text[start:end].replace("\n", " ").strip()
            seen[key] = Secret(kind=kind, value=value, severity=sev, context=ctx)
    # one entry per distinct value — keep the highest-severity classification
    by_value: dict[str, Secret] = {}
    for sec in seen.values():
        cur = by_value.get(sec.value)
        if cur is None or _SEV_RANK.get(sec.severity, 0) > _SEV_RANK.get(cur.severity, 0):
            by_value[sec.value] = sec
    return sorted(by_value.values(), key=lambda x: _SEV_RANK.get(x.severity, 0), reverse=True)


def to_session_header(secret: Secret) -> dict[str, str]:
    """If a secret is directly usable as an auth header, return it (else {})."""
    import base64

    if secret.kind in ("bearer_token", "jwt"):
        return {"Authorization": f"Bearer {secret.value}"}
    if secret.kind == "generic_api_key":
        return {"X-API-Key": secret.value}
    if secret.kind == "basic_auth_url":
        m = re.match(r"https?://([^/\s:@\"']{1,64}):([^/\s@\"']{1,64})@", secret.value)
        if m:
            enc = base64.b64encode(f"{m.group(1)}:{m.group(2)}".encode()).decode()
            return {"Authorization": f"Basic {enc}"}
    return {}
