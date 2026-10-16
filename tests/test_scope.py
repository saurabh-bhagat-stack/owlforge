"""Assessment scope resolver."""

from __future__ import annotations

from owlforge.engine.scope import build_scope


def test_scope_primary_include_exclude_and_classes():
    sc = build_scope("https://ui.abc.com/", scope=["api.abc.com", "*/public/*"],
                      out_of_scope=["*/admin/*", "/logout"], only=["xss", "sqli"])
    assert sc.in_scope("https://ui.abc.com/catalog")          # primary host
    assert sc.in_scope("https://api.abc.com/v1/users")        # explicit include host
    assert not sc.in_scope("https://ui.abc.com/admin/panel")  # excluded path glob
    assert not sc.in_scope("https://ui.abc.com/logout")       # excluded exact path
    assert not sc.in_scope("https://evil.com/x")              # off-scope host
    assert sc.allows_class("xss") and not sc.allows_class("rce")


def test_scope_auto_includes_app_reached_host():
    sc = build_scope("https://ui.abc.com/")
    assert not sc.in_scope("https://api.abc.com/x")
    sc.allow_host("api.abc.com")
    assert sc.in_scope("https://api.abc.com/x")


def test_scope_exclusion_wins_over_include():
    sc = build_scope("https://t.com/", scope=["t.com/*"], out_of_scope=["t.com/secret*"])
    assert sc.in_scope("https://t.com/ok")
    assert not sc.in_scope("https://t.com/secret/data")


def test_run_recon_filters_out_of_scope(monkeypatch, tmp_path):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    import owlforge.engine.recon as recon

    target = "https://ui.abc.com/"
    inv = [
        {"url": "https://ui.abc.com/catalog", "method": "GET", "params": ["q"], "source": "html"},
        {"url": "https://ui.abc.com/admin/panel", "method": "GET", "params": [], "source": "link"},
        {"url": "https://api.abc.com/v1/users", "method": "GET", "params": [], "source": "js"},
        {"url": "https://cdn.other.com/lib.js", "method": "GET", "params": [], "source": "js"},
    ]
    sc = build_scope(target, out_of_scope=["*/admin/*"])
    kept = {it["url"] for it in recon._apply_scope(inv, target, sc)}
    assert "https://ui.abc.com/catalog" in kept          # primary
    assert "https://api.abc.com/v1/users" in kept         # same reg-domain, auto-included
    assert "https://ui.abc.com/admin/panel" not in kept   # excluded
    assert "https://cdn.other.com/lib.js" not in kept     # cross-domain, not auto-included
