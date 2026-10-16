"""Broad secret/sensitive-info scanner."""

from __future__ import annotations

from owlforge.engine.secrets import scan_text, to_session_header


def test_scan_catches_common_secret_classes_with_full_values():
    text = (
        'aws = "AKIA1234567890ABCDEF";\n'
        'db = "postgresql://user:p4ssw0rd@10.0.0.9:5432/prod";\n'
        'const u = "https://admin:hunter2@internal.svc/api";\n'
        'headers = { Authorization: "Bearer abcDEF012345678901234567" };\n'
        'pk = "-----BEGIN RSA PRIVATE KEY-----";\n'
    )
    hits = {s.kind: s for s in scan_text(text)}
    assert hits["aws_access_key_id"].value == "AKIA1234567890ABCDEF"      # full value, no redaction
    assert hits["db_connection_string"].value.startswith("postgresql://user:p4ssw0rd@")
    assert "hunter2" in hits["basic_auth_url"].value
    assert hits["bearer_token"].value == "abcDEF012345678901234567"
    assert hits["private_key"].severity == "critical"


def test_scan_skips_obvious_placeholders():
    text = 'apiKey: "your_api_key_here", token: "xxxxxxxxxxxx", password: "changeme123"'
    assert scan_text(text) == []


def test_to_session_header_for_usable_creds():
    (bearer,) = [s for s in scan_text('Authorization: "Bearer tok12345678901234567890"')]
    assert to_session_header(bearer) == {"Authorization": "Bearer tok12345678901234567890"}
    (basic,) = [s for s in scan_text('u="https://a:b@host/x"')]
    assert to_session_header(basic)["Authorization"].startswith("Basic ")
