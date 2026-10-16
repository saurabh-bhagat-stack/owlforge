"""Identity / role manager + dependency-free TOTP."""

from __future__ import annotations

from owlforge.engine.identities import (
    establish_identity,
    load_identities,
    primary_identity,
    totp_now,
)


def test_totp_rfc6238_sha1_vector():
    # base32 of "12345678901234567890"; RFC 6238 T=59 (SHA-1) -> 94287082 -> 6 digits 287082
    assert totp_now("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", for_time=59) == "287082"


def test_load_identities_prepends_unauth(tmp_path):
    f = tmp_path / "ids.yaml"
    f.write_text(
        "identities:\n"
        "  - {label: admin, role: admin, auth: {type: cookie, cookie: 'session=a'}}\n"
        "  - {label: alice, role: user, auth: {type: header, header: 'Authorization: Bearer x'}}\n"
    )
    ids = load_identities(str(f))
    assert [i.label for i in ids] == ["unauth", "admin", "alice"]
    assert ids[0].role == "anonymous"


def test_establish_cookie_header_and_login_with_totp():
    from owlforge.engine.identities import Identity
    cookie = Identity(label="c", auth={"type": "cookie", "cookie": "session=abc"})
    assert establish_identity(cookie, lambda *a, **k: {}) == {"Cookie": "session=abc"}

    header = Identity(label="h", auth={"type": "header", "header": "Authorization: Bearer tok"})
    assert establish_identity(header, lambda *a, **k: {}) == {"Authorization": "Bearer tok"}

    seen = {}
    def reqfn(method, url, headers=None, params=None, body=None):
        seen["body"] = body or ""
        return {"status": 200, "headers": {"set-cookie": "session=xyz; Path=/"}, "body": "Welcome"}

    login = Identity(label="l", auth={"type": "login", "url": "https://t/login",
                                      "data": "username=u&password=p", "success": "Welcome",
                                      "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
    h = establish_identity(login, reqfn)
    assert "otp=" in seen["body"]                 # generated TOTP was submitted
    assert h.get("Cookie") == "session=xyz"


def test_sso_defers_and_primary_prefers_privileged():
    from owlforge.engine.identities import Identity
    sso = Identity(label="s", auth={"type": "sso"})
    establish_identity(sso, lambda *a, **k: {})
    assert sso.needs_sso and not sso.session_headers

    ids = [
        Identity(label="unauth", role="anonymous", auth={"type": "unauth"}),
        Identity(label="alice", role="user", session_headers={"Cookie": "u=1"}),
        Identity(label="admin", role="admin", session_headers={"Cookie": "a=1"}),
    ]
    assert primary_identity(ids).label == "admin"   # privileged role wins
