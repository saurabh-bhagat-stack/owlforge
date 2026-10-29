"""Pre-flight identity verification: good session ✓, bad session ✗, anonymous –."""
from __future__ import annotations

from owlforge.engine.identities import verify_identities


def _reqfn(method, url, headers=None, params=None, body=None):
    cookie = (headers or {}).get("Cookie", "")
    if "good" in cookie:
        return {"status": 200, "body": "<h1>My account</h1> Welcome carlos — Log out"}
    return {"status": 401, "body": "Unauthorized"}


def test_preflight_flags_good_bad_and_anonymous():
    ids = [
        {"label": "unauth", "role": "anonymous", "headers": {}},
        {"label": "alice", "role": "user", "headers": {"Cookie": "s=good"}},
        {"label": "bob", "role": "user", "headers": {"Cookie": "s=bad"}},
    ]
    res = verify_identities(ids, _reqfn, "https://t/account")
    by = {r["label"]: r["ok"] for r in res}
    assert by["unauth"] is None      # anonymous — not a credential to verify
    assert by["alice"] is True       # valid session
    assert by["bob"] is False        # 401 -> caught before the scan


def test_preflight_empty_is_safe():
    assert verify_identities([], _reqfn, "https://t/") == []
