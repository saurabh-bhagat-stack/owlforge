"""Low-friction --cred / --session parsing."""
from __future__ import annotations

from owlforge.engine.authspec import parse_creds, parse_curl, parse_sessions


def test_cred_single_colon():
    c = parse_creds(["carlos:hunter2"])
    assert c == [{"label": "carlos", "role": "user", "user": "carlos",
                  "password": "hunter2", "order": 0}]


def test_cred_space_separator():
    c = parse_creds(["carlos hunter2"])
    assert c[0]["user"] == "carlos" and c[0]["password"] == "hunter2"


def test_cred_comma_multi_for_idor():
    c = parse_creds(["alice:pw1, bob:pw2"])
    assert [x["user"] for x in c] == ["alice", "bob"]
    assert c[0]["order"] == 0 and c[1]["order"] == 1   # two identities -> horizontal IDOR


def test_cred_role_suffix_and_label():
    c = parse_creds(["root:toor:admin", "@boss manager1:pw"])
    assert c[0]["role"] == "admin" and c[0]["password"] == "toor"
    assert c[1]["label"] == "boss" and c[1]["user"] == "manager1"


def test_cred_admin_label_infers_role():
    assert parse_creds(["administrator:x"])[0]["role"] == "admin"


def test_cred_password_with_colon_preserved():
    c = parse_creds(["user:a:b:c"])          # no trailing role word -> whole tail is the password
    assert c[0]["user"] == "user" and c[0]["password"] == "a:b:c"


def test_session_cookie_string():
    s = parse_sessions(["session=abc123; csrf=xyz"])
    assert s[0]["headers"] == {"Cookie": "session=abc123; csrf=xyz"}


def test_session_bearer_header():
    s = parse_sessions(["Authorization: Bearer eyJhbGci.payload.sig"])
    assert s[0]["headers"] == {"Authorization": "Bearer eyJhbGci.payload.sig"}


def test_session_custom_header():
    s = parse_sessions(["X-API-Key: k123"])
    assert s[0]["headers"] == {"X-API-Key": "k123"}


def test_session_multiple_headers_pipe():
    s = parse_sessions(["Cookie: a=b | X-API-Key: k123"])
    assert s[0]["headers"] == {"Cookie": "a=b", "X-API-Key": "k123"}


def test_session_label_and_role():
    s = parse_sessions(["@admin Authorization: Bearer t"])
    assert s[0]["label"] == "admin" and s[0]["role"] == "admin"
    assert s[0]["headers"]["Authorization"] == "Bearer t"


def test_session_multiple_identities():
    s = parse_sessions(["@alice Cookie: s=1", "@bob Cookie: s=2"])
    assert [x["label"] for x in s] == ["alice", "bob"]


def test_parse_curl_paste():
    cmd = ("curl 'https://app.example/account' "
           "-H 'Authorization: Bearer eyJ.a.b' "
           "-H 'Cookie: session=deadbeef' --compressed")
    h = parse_curl(cmd)
    assert h["Authorization"] == "Bearer eyJ.a.b" and h["Cookie"] == "session=deadbeef"


def test_session_from_curl():
    s = parse_sessions(["curl 'https://app/' -b 'sid=123' -H 'X-CSRF: tok'"])
    assert s[0]["headers"]["Cookie"] == "sid=123" and s[0]["headers"]["X-CSRF"] == "tok"
