"""Deterministic CVSS v3.1 base scores/vectors per finding class.

A mapping (not a live computation): each vulnerability class gets a representative CVSS 3.1
base vector + score so reports carry a professional, consistent rating. Unknown classes fall
back to a score implied by the finding's severity.
"""

from __future__ import annotations

# keyword(s) in the lowercased title -> (score, CVSS:3.1 vector, label)
_MAP: list[tuple[tuple[str, ...], float, str]] = [
    (("alg=none", "jwt", "guessable secret", "weak/guessable"),
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),               # auth bypass / token forgery
    (("sql injection", "sqli"), 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (("command injection", "os command", "rce", "remote code"),
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (("server-side template", "ssti", "template injection"),
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (("nosql",), 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (("deserializ",), 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (("file upload", "webshell"), 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    (("xml external", "xxe"), 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L"),
    (("ssrf", "server-side request"), 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    (("idor", "insecure direct object", "broken access", "access control", "bola", "privilege"),
     8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"),
    (("path traversal", "lfi", "local file", "directory traversal"),
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (("request smuggling", "smuggl"), 7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N"),
    (("csrf", "cross-site request"), 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    (("cross-site scripting", "xss"), 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (("open redirect",), 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (("crlf", "response splitting", "header injection"),
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (("graphql",), 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (("websocket",), 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (("secret", "api key", "token", "credential", "password", "disclosure"),
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (("csp", "content-security", "hsts", "strict-transport", "x-content-type", "clickjack",
      "cookie", "cors", "security header",
      "directory listing", "verbose error", "stack trace", "version disclosure", "host header"),
     4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
]

_SEV_FALLBACK = {"critical": 9.0, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}
_VEC_FALLBACK = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "low": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


def cvss(title: str, severity: str = "medium") -> tuple[float, str]:
    """Return (base_score, vector) for a finding title; fall back to its severity."""
    t = (title or "").lower()
    for keys, score, vector in _MAP:
        if any(k in t for k in keys):
            return score, vector
    sev = (severity or "medium").lower()
    return _SEV_FALLBACK.get(sev, 5.0), _VEC_FALLBACK.get(sev, _VEC_FALLBACK["medium"])
