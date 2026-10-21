"""CSRF token handling + CSRF vuln-class planning."""

from __future__ import annotations

from owlforge.engine.csrf import extract_token, fresh_token, with_fresh_token


def test_extract_token_from_hidden_input_and_meta():
    assert extract_token('<input type="hidden" name="csrf_token" value="TOK1">') == ("csrf_token", "TOK1")
    assert extract_token('<input name="__RequestVerificationToken" value="NET2">') == (
        "__RequestVerificationToken", "NET2")
    assert extract_token('<meta name="csrf-token" content="M3">') == ("csrf-token", "M3")
    assert extract_token('<input name="username" value="x">') is None


def test_fresh_and_with_fresh_token_handle_rotation():
    calls = {"n": 0}

    def reqfn(method, url, headers=None, params=None, body=None):
        calls["n"] += 1
        return {"status": 200, "body": f'<input name="_csrf" value="rot{calls["n"]}">'}

    assert fresh_token(reqfn, "https://t/form") == ("_csrf", "rot1")
    merged = with_fresh_token(reqfn, "https://t/form", {"email": "a@b.c"})
    assert merged == {"email": "a@b.c", "_csrf": "rot2"}   # re-fetched a fresh (rotated) token


def test_plan_tasks_adds_csrf_for_state_changing_endpoints():
    from owlforge.engine.classify import CSRF
    from owlforge.engine.orchestrator import plan_tasks

    inv = [
        {"url": "https://t/login", "method": "POST", "params": ["username", "csrf"]},
        {"url": "https://t/account/email", "method": "POST", "params": []},
        {"url": "https://t/catalog", "method": "GET", "params": ["category"]},
    ]
    tasks = plan_tasks(inv)
    csrf_urls = {t["url"] for t in tasks.get(CSRF, [])}
    assert csrf_urls == {"https://t/login", "https://t/account/email"}   # POSTs only, not the GET


# --- deterministic CSRF enforcement probe ---

def _db(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


_FORM = (
    '<form action="/account/email" method=POST>'
    '<input type=hidden name="csrf" value="REALTOKEN123">'
    '<input type=hidden name="returnTo" value="/account">'
    '<input type=text name="email" value="a@b.c">'
    '<button>save</button></form>'
)


class _Sandbox:
    """GET returns the form; POST returns whatever `post_status`/`post_body` say."""

    def __init__(self, post_status, post_body="", loc=""):
        self.post_status = post_status
        self.post_body = post_body
        self.loc = loc
        self.posts = []

    def http_request(self, method, url, *, headers=None, params=None, body=None,
                     follow_redirects=True, timeout_ms=30000):
        if method == "GET":
            return {"status": 200, "headers": {}, "body": _FORM}
        self.posts.append((url, body))
        h = {"location": self.loc} if self.loc else {}
        return {"status": self.post_status, "headers": h, "body": self.post_body}


_INV = [{"url": "https://t.test/account/email", "method": "POST",
         "params": ["csrf", "returnTo", "email"], "source": "form"}]


def test_corrupted_token_accepted_is_candidate(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.csrf import csrf_scan
    from owlforge.store.models import Finding
    sb = _Sandbox(post_status=200, post_body="Email updated")
    n = csrf_scan("a", _INV, sb, session_headers={"Cookie": "session=x"})
    assert n == 1
    # the corrupted token was actually sent (not the real one)
    assert sb.posts and "REALTOKEN123" not in sb.posts[0][1]
    with db.session() as s:
        from sqlmodel import select
        f = s.exec(select(Finding).where(Finding.assessment_id == "a")).all()
    assert len(f) == 1 and f[0].status == "candidate" and "CSRF" in f[0].title.upper()


def test_corrupted_token_rejected_files_nothing(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    from owlforge.engine.csrf import csrf_scan
    from owlforge.store.models import Finding
    sb = _Sandbox(post_status=403, post_body="Invalid CSRF token")
    n = csrf_scan("a", _INV, sb, session_headers={"Cookie": "session=x"})
    assert n == 0
    with db.session() as s:
        from sqlmodel import select
        assert s.exec(select(Finding).where(Finding.assessment_id == "a")).all() == []


def test_no_token_form_is_skipped(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    from owlforge.engine.csrf import csrf_scan
    inv = [{"url": "https://t.test/x", "method": "POST", "params": ["email"], "source": "form"}]
    assert csrf_scan("a", inv, _Sandbox(200), session_headers={}) == 0


def test_no_sandbox_is_noop():
    from owlforge.engine.csrf import csrf_scan
    assert csrf_scan("a", _INV, None, session_headers={}) == 0
