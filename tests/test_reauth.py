"""Mid-scan session liveness + automatic re-login (fresh TOTP)."""
from __future__ import annotations


def test_session_alive_signals():
    from owlforge.engine.identities import session_alive
    def ok(m, u, headers=None):
        return {"status": 200, "body": "Welcome to your dashboard"}
    assert session_alive(ok, "https://t/account", {}) is True
    assert session_alive(lambda m, u, headers=None: {"status": 401}, "https://t", {}) is False
    assert session_alive(lambda m, u, headers=None: {"status": 403}, "https://t", {}) is False

    login_body = "<form method=post><input name=username><input name=password type=password></form> please log in"
    assert session_alive(lambda m, u, headers=None: {"status": 200, "body": login_body}, "https://t", {}) is False

    redir = {"status": 302, "headers": {"location": "https://t/login?next=/account"}}
    assert session_alive(lambda m, u, headers=None: redir, "https://t", {}) is False

    def boom(*a, **k):
        raise RuntimeError("net")
    assert session_alive(boom, "https://t", {}) is True        # unknown -> assume alive


def test_reauth_login_injects_fresh_totp(monkeypatch):
    import owlforge.engine.auth as auth
    captured = {}

    def fake_establish(ctx, request_fn, log=None):
        captured["params"] = dict(ctx.login_params)
        captured["url"] = ctx.login_url
        return {"Cookie": "fresh=1"}

    monkeypatch.setattr(auth, "establish_session", fake_establish)
    from owlforge.engine.identities import reauth_login
    spec = {"url": "https://t/login", "data": "username=alice&password=x", "success": "Welcome",
            "totp_secret": "JBSWY3DPEHPK3PXP", "totp_field": "otp"}
    headers = reauth_login(spec, lambda *a, **k: {})
    assert headers == {"Cookie": "fresh=1"}
    assert captured["url"] == "https://t/login"
    assert captured["params"]["username"] == "alice"
    assert captured["params"]["otp"].isdigit() and len(captured["params"]["otp"]) == 6
