"""CVSS v3.1 class mapping."""
from owlforge.report.cvss import cvss


def test_class_scores():
    assert cvss("SQL injection in category", "high")[0] == 9.8
    assert cvss("JWT 'alg=none' accepted", "critical")[0] == 9.8
    assert cvss("Reflected XSS", "medium")[0] == 6.1
    assert cvss("Broken access control (IDOR)", "high")[0] == 8.1
    assert cvss("Missing Content-Security-Policy", "low")[0] == 4.3
    assert all(cvss(t, "high")[1].startswith("CVSS:3.1/") for t in
               ("SQL injection", "Reflected XSS", "x"))


def test_severity_fallback_for_unknown():
    assert cvss("Totally novel issue", "critical")[0] == 9.0
    assert cvss("Totally novel issue", "low")[0] == 3.1
