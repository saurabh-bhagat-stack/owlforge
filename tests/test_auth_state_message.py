"""The auth-boundary visibility line: a run with no authenticated session must say so loudly, so a
degraded run (signup/login failed) is never mistaken for a clean app."""
from __future__ import annotations

from owlforge.cli import _auth_state_message


def test_unauthenticated_is_announced():
    n, msg = _auth_state_message(None, [{"label": "unauth", "role": "anonymous", "headers": {}}])
    assert n == 0
    assert "UNAUTHENTICATED" in msg and "--cred" in msg


def test_single_session_counts():
    n, msg = _auth_state_message({"Cookie": "session=x"}, None)
    assert n == 1 and "1 authenticated identity" in msg


def test_two_registered_identities_counted():
    idents = [{"label": "unauth", "role": "anonymous", "headers": {}},
              {"label": "a", "role": "user", "headers": {"Authorization": "Bearer A"}},
              {"label": "b", "role": "user", "headers": {"Authorization": "Bearer B"}}]
    n, msg = _auth_state_message(None, idents)
    assert n == 2 and "2 authenticated identities" in msg


def test_anon_only_identity_set_is_unauthenticated():
    n, _ = _auth_state_message(None, [{"label": "unauth", "role": "anon", "headers": {}}])
    assert n == 0
