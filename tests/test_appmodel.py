"""App model — deterministic structural extraction from the mapped surface."""
from __future__ import annotations

from owlforge.engine.appmodel import (
    CREATE,
    DELETE,
    EDIT,
    LOGIN,
    LOGOUT,
    REGISTER,
    TRANSITION,
    UPLOAD,
    build_app_model,
    classify_action,
)


def test_classify_action_kinds():
    assert classify_action("https://t/register", "POST", ["email", "password", "confirm"]) == REGISTER
    assert classify_action("https://t/login", "POST", ["username", "password"]) == LOGIN
    assert classify_action("https://t/logout", "GET", []) == LOGOUT
    assert classify_action("https://t/avatar", "POST", ["avatar"]) == UPLOAD
    assert classify_action("https://t/orders/5/approve", "POST", []) == TRANSITION
    assert classify_action("https://t/posts/5", "DELETE", []) == DELETE
    assert classify_action("https://t/account/edit", "POST", ["name"]) == EDIT
    assert classify_action("https://t/posts", "POST", ["title", "body"]) == CREATE


def test_entity_and_roles_and_workflow():
    inv = [
        {"url": "https://t/posts", "method": "POST", "params": ["title", "body"], "source": "form"},
        {"url": "https://t/posts/5/publish", "method": "POST", "params": [], "source": "form"},
        {"url": "https://t/posts/5/delete", "method": "POST", "params": [], "source": "form"},
        {"url": "https://t/login", "method": "POST", "params": ["user", "password"], "source": "form"},
        {"url": "https://t/logout", "method": "GET", "params": [], "source": "link"},
    ]
    idents = [
        {"label": "unauth", "role": "anonymous", "headers": {}},
        {"label": "alice", "role": "user", "headers": {"Cookie": "a=1"}},
        {"label": "admin", "role": "admin", "headers": {"Cookie": "b=1"}},
    ]
    m = build_app_model(inv, idents, seeded_urls=["https://t/posts/5"], tech=["flask"])
    names = [e.name for e in m.entities]
    assert "post" in names
    post = next(e for e in m.entities if e.name == "post")
    kinds = {a.kind for a in post.actions}
    assert {CREATE, TRANSITION, DELETE} <= kinds
    assert "https://t/posts/5" in post.instances
    # roles: admin flagged privileged, two have sessions
    assert any(r.privileged and r.label == "admin" for r in m.roles)
    assert len([r for r in m.roles if r.headers]) == 2
    # workflows: an auth flow + a post lifecycle (>= 2 ordered steps)
    wf_names = [w.name for w in m.workflows]
    assert "authentication" in wf_names
    assert any("post lifecycle" == w.name and len(w.steps) >= 2 for w in m.workflows)
    assert m.is_interesting()
    assert "Entities:" in m.summary()
    assert "flask" in m.summary()


def test_not_interesting_when_bare():
    m = build_app_model(
        [{"url": "https://t/about", "method": "GET", "params": [], "source": "link"}],
        [{"label": "unauth", "role": "anonymous", "headers": {}}],
    )
    assert not m.is_interesting()
