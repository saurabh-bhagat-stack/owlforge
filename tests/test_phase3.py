"""Phase 3: typed findings, evidence-gated validation, report assembly."""

from __future__ import annotations

import asyncio

import pytest

from owlforge.engine.events import Emitter
from owlforge.sandbox.client import ExecResult


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import owlforge.config as config
    import owlforge.store.db as db

    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    return db


class _FakeSandbox:
    def __init__(self, out: str) -> None:
        self.out = out

    def exec(self, command: str, *, workdir=None, timeout_ms=60_000) -> ExecResult:
        return ExecResult(exit_code=0, stdout=self.out, stderr="", duration_ms=1)

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
        # emulate ginandjuice: a lone quote in category -> 500, else 200
        q = (params or {}).get("category", "")
        status = 500 if q == "'" else 200
        return {"status": status, "headers": {}, "body": self.out}


def _mk(db, **kw):
    from owlforge.store.models import Finding

    f = Finding(assessment_id="asmt_x", status="candidate", **kw)
    with db.session() as s:
        s.add(f)
        s.commit()
        return f.id


def test_validation_promotes_on_signal_rejects_without_and_manual_without_repro(isolated):
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    good = _mk(isolated, id="f_good", title="LFI /etc/passwd", severity="high",
               repro_command="curl .../?file=/etc/passwd", success_signal="root:x:0:0")
    bad = _mk(isolated, id="f_bad", title="maybe xss", severity="low",
              repro_command="curl ...", success_signal="UNIQUE_MARKER_123")
    manual = _mk(isolated, id="f_manual", title="suspected info disclosure", severity="medium")

    # sandbox output contains the good signal but not the bad one
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_FakeSandbox("root:x:0:0:root:/root:/bin/bash"),
        emit=Emitter("asmt_x", persist=False)))

    assert counts == {"validated": 1, "rejected": 1, "manual": 1}
    with isolated.session() as s:
        assert s.get(Finding, good).status == "validated"
        assert s.get(Finding, bad).status == "false_positive"
        assert s.get(Finding, manual).status == "candidate"
        assert "manual" in s.get(Finding, manual).validation_note.lower()


def test_report_build(isolated):
    from owlforge.report.builder import build_and_save_report
    from owlforge.store.models import Assessment, Finding

    with isolated.session() as s:
        s.add(Assessment(id="asmt_x", project_name="p", target="https://t.test",
                         instructions="i", scan_mode="standard", status="reporting"))
        s.add(Finding(id="f1", assessment_id="asmt_x", title="SQLi login", severity="critical",
                      status="validated", confidence="high", endpoint="/login",
                      proof_of_concept="' OR 1=1--", repro_command="sqlmap ...",
                      impact="auth bypass", remediation="use params"))
        s.commit()

    md, path = build_and_save_report("asmt_x")
    assert "SQLi login" in md and "Overall risk: **Critical**" in md
    assert path and path.endswith("report.md")


def test_create_finding_tool_persists_no_detached_error(isolated):
    from sqlmodel import select

    from owlforge.store.models import Finding
    from owlforge.tools.base import ToolContext
    from owlforge.tools.builtin import build_registry

    tool = build_registry(with_sandbox=False).get("create_finding")
    assert tool is not None
    ctx = ToolContext(assessment_id="asmt_x", target="https://t.test", emit=Emitter("asmt_x", persist=False))
    out = asyncio.run(tool.run(
        {"title": "Test XSS", "severity": "high", "repro_command": "curl x", "success_signal": "X"}, ctx))
    assert "filed as candidate" in out and "error" not in out.lower()
    with isolated.session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == "asmt_x")).all()
    assert len(rows) == 1 and rows[0].title == "Test XSS"


def test_validation_rejects_html_encoded_only_reflection(isolated):
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    fid = _mk(isolated, id="f_esc", title="reflected XSS?", severity="high",
              repro_command="curl ...", success_signal="<script>owl</script>")
    # Sandbox returns the payload ONLY in HTML-encoded form -> escaped -> not exploitable.
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x",
        sandbox=_FakeSandbox("var s = '&lt;script&gt;owl&lt;/script&gt;';"),
        emit=Emitter("asmt_x", persist=False)))
    assert counts["rejected"] == 1 and counts["validated"] == 0
    with isolated.session() as s:
        assert s.get(Finding, fid).status == "false_positive"


def test_normalize_params_prevents_double_encoding():
    from owlforge.tools.builtin import _normalize_params

    # pre-encoded payload gets decoded once (so httpx encodes exactly once on the wire)
    assert _normalize_params({"category": "Accessories%27"}) == {"category": "Accessories'"}
    # raw payload is left as-is
    assert _normalize_params({"category": "Accessories'"}) == {"category": "Accessories'"}
    # plain values untouched
    assert _normalize_params({"q": "plain"}) == {"q": "plain"}


def test_playbooks_teach_enumeration_and_confirmation():
    from owlforge.knowledge import load_playbooks, render_playbooks

    names = {p["name"] for p in load_playbooks()}
    assert {"methodology", "sql_injection", "xss", "path_traversal"} <= names
    text = render_playbooks()
    # the discovery-gap fix: enumerate ALL params, not just the obvious one
    assert "EVERY input point" in text
    assert "BREADTH BEFORE DEPTH" in text
    # the escaped-reflection lesson
    assert "HTML-ENCODED" in text and "NOT exploitable" in text


def test_system_prompt_includes_playbooks():
    from owlforge.engine.prompts import system_prompt

    sp = system_prompt("https://t.test", "assess it", "standard")
    # the methodology overview is always present; per-class packs are injected per
    # specialist (not dumped here), so the focused prompt stays lean for weak models
    assert "Methodology" in sp and "MAP the attack surface" in sp
    assert "UNION SELECT" not in sp and "template expression" not in sp


def test_access_control_finding_not_auto_validated(isolated):
    import asyncio

    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    fid = _mk(isolated, id="f_idor", title="Broken Access Control / IDOR on products",
              severity="high", repro_command="curl .../product?productId=2", success_signal="Cocktail")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_FakeSandbox("... Create Your Own Cocktail ..."),
        emit=Emitter("asmt_x", persist=False)))
    # signal WOULD be present, but access-control must NOT auto-validate
    assert counts["validated"] == 0 and counts["manual"] == 1
    with isolated.session() as s:
        f = s.get(Finding, fid)
        assert f.status == "candidate" and "differential" in f.validation_note.lower()


def test_migration_adds_missing_column(tmp_path, monkeypatch):
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    import importlib

    import owlforge.config as config
    importlib.reload(config)
    import owlforge.store.db as db
    importlib.reload(db)
    from sqlalchemy import text

    db._engine = None
    db.init_db()
    # simulate an OLD schema: drop a column by recreating a stripped finding table is hard;
    # instead, add then verify idempotency + that a known new column exists after migrate.
    with db.get_engine().begin() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info('finding')")).all()]
    assert "repro_command" in cols and "success_signal" in cols and "validation_note" in cols
    # simulate stale table missing 'validation_note'
    with db.get_engine().begin() as conn:
        conn.execute(text("ALTER TABLE finding DROP COLUMN validation_note"))
        cols2 = [r[1] for r in conn.execute(text("PRAGMA table_info('finding')")).all()]
    assert "validation_note" not in cols2
    db.init_db()  # migration should re-add it
    with db.get_engine().begin() as conn:
        cols3 = [r[1] for r in conn.execute(text("PRAGMA table_info('finding')")).all()]
    assert "validation_note" in cols3


def test_structured_repro_validates_via_http_request(isolated):
    import asyncio

    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    fid = _mk(isolated, id="f_sqli", title="SQL Injection in category parameter", severity="high",
              repro_url="https://t/catalog", repro_method="GET",
              repro_params={"category": "'"}, success_signal="500")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_FakeSandbox(""), emit=Emitter("asmt_x", persist=False)))
    assert counts["validated"] == 1
    with isolated.session() as s:
        assert s.get(Finding, fid).status == "validated"


class _XssSandbox(_FakeSandbox):
    """Fake whose /xss_check reports execution when a payload reaches the `exec`-param."""
    def __init__(self, executes: bool) -> None:
        super().__init__("")
        self.executes = executes

    def xss_check(self, url, token, *, headers=None, timeout_ms=15_000):
        return {"executed": self.executes and ("onerror" in url or "script" in url),
                "via": "script-exec (window.__owl_xss)" if self.executes else "", "status": 200}


def test_browser_xss_validated_on_execution(isolated):
    from owlforge.engine.validate import validate_findings

    fid = _mk(isolated, id="f_xss_exec", title="Reflected XSS in search", severity="high",
              repro_url="https://t/search", repro_method="GET",
              repro_params={"q": "<img src=x onerror=alert(1)>"}, success_signal="owl")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_XssSandbox(True), emit=Emitter("asmt_x", persist=False)))
    assert counts["validated"] == 1 and counts["rejected"] == 0
    from owlforge.store.models import Finding
    with isolated.session() as s:
        assert "EXECUTED" in (s.get(Finding, fid).validation_note or "")


def test_browser_xss_rejected_when_not_executing(isolated):
    from owlforge.engine.validate import validate_findings

    _mk(isolated, id="f_xss_noexec", title="Reflected XSS in search", severity="high",
        repro_url="https://t/search", repro_method="GET",
        repro_params={"q": "<script>alert(1)</script>"}, success_signal="owl")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_XssSandbox(False), emit=Emitter("asmt_x", persist=False)))
    assert counts["rejected"] == 1 and counts["validated"] == 0


class _DiffSandbox:
    """Fake for differential access-control: `protected` decides whether the anon
    (no-session) request is denied (401) or returns the same resource as authed."""
    def __init__(self, protected: bool) -> None:
        self.protected = protected

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
        authed = bool(headers)
        if not authed and self.protected:
            return {"status": 401, "headers": {}, "body": "nope"}
        return {"status": 200, "headers": {}, "body": "ACCOUNT DETAILS: balance=4210 user=carlos " * 4}


def test_differential_access_validates_when_reachable_anonymously(isolated):
    from owlforge.engine.validate import validate_findings

    fid = _mk(isolated, id="f_bac", title="Broken Access Control on /my-account",
              severity="high", repro_url="https://t/my-account", repro_method="GET")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_DiffSandbox(protected=False),
        emit=Emitter("asmt_x", persist=False), session_headers={"Cookie": "s=1"}))
    assert counts["validated"] == 1
    from owlforge.store.models import Finding
    with isolated.session() as s:
        assert "anonymously" in (s.get(Finding, fid).validation_note or "")


def test_differential_access_rejects_when_boundary_enforced(isolated):
    from owlforge.engine.validate import validate_findings

    _mk(isolated, id="f_bac2", title="IDOR on account", severity="high",
        repro_url="https://t/my-account", repro_method="GET")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_DiffSandbox(protected=True),
        emit=Emitter("asmt_x", persist=False), session_headers={"Cookie": "s=1"}))
    assert counts["rejected"] == 1 and counts["validated"] == 0


def test_access_control_stays_manual_without_session(isolated):
    from owlforge.engine.validate import validate_findings

    _mk(isolated, id="f_bac3", title="IDOR on account", severity="high",
        repro_url="https://t/my-account", repro_method="GET")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_DiffSandbox(protected=True),
        emit=Emitter("asmt_x", persist=False), session_headers=None))
    assert counts["manual"] == 1


def test_understand_secrets_files_and_validates_info_disclosure(isolated):
    from owlforge.engine.recon import understand_secrets
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    leak = 'const cfg = { stripe: "sk_live_ABCDEF0123456789abcdef" };'

    def reqfn(method, url, headers=None, params=None, body=None):
        if url.endswith("/static/app.js"):
            return {"status": 200, "body": leak}
        return {"status": 404, "body": ""}

    inv = [{"url": "https://t/static/app.js", "method": "GET", "params": [], "source": "js"}]
    creds, prov = understand_secrets("asmt_x", "https://t/", inv, reqfn)

    with isolated.session() as sess:
        rows = [f for f in sess.exec(__import__("sqlmodel").select(Finding)).all()]
    assert len(rows) == 1
    f = rows[0]
    assert f.status == "candidate" and "Information disclosure" in f.title
    assert f.evidence == "sk_live_ABCDEF0123456789abcdef"      # full value kept as proof

    # the existing evidence gate re-fetches and confirms the secret is actually served
    class _ServesSecret:
        def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
            return {"status": 200, "headers": {}, "body": leak}
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_x", sandbox=_ServesSecret(), emit=Emitter("asmt_x", persist=False)))
    assert counts["validated"] == 1


def test_dedupe_collapses_same_class_endpoint_keeps_best(isolated):
    from owlforge.engine.validate import dedupe_findings
    from owlforge.store.models import Finding

    def seed(fid, title, severity, status, params):
        with isolated.session() as s:
            s.add(Finding(id=fid, assessment_id="asmt_x", title=title, severity=severity,
                          status=status, repro_url="https://t/catalog", repro_method="GET",
                          repro_params=params))
            s.commit()

    # same class+endpoint+params: a validated and a candidate -> candidate becomes duplicate
    seed("d1", "SQL Injection in category", "high", "validated", {"category": "'"})
    seed("d2", "SQLi via category param", "medium", "candidate", {"category": "'"})
    # a different class on the same endpoint must NOT be merged
    seed("d3", "Reflected XSS in category", "medium", "candidate", {"category": "<x>"})

    collapsed = dedupe_findings("asmt_x")
    assert collapsed == 1
    with isolated.session() as sess:
        assert sess.get(Finding, "d1").status == "validated"
        assert sess.get(Finding, "d2").status == "duplicate"
        assert sess.get(Finding, "d3").status == "candidate"   # different class, kept


def test_dedupe_keeps_distinct_observational_titles_same_endpoint(isolated):
    from owlforge.engine.validate import dedupe_findings
    from owlforge.store.models import Finding

    def seed(fid, title):
        with isolated.session() as s:
            s.add(Finding(id=fid, assessment_id="asmt_o", title=title, severity="low",
                          status="candidate", endpoint="https://t/", method="GET"))
            s.commit()

    # distinct passive issues on the SAME endpoint must NOT be merged
    seed("o1", "Missing Content-Security-Policy")
    seed("o2", "Missing HSTS")
    seed("o3", "Missing X-Content-Type-Options: nosniff")
    # a true duplicate (same title, same endpoint) SHOULD merge
    seed("o4", "Missing HSTS")

    collapsed = dedupe_findings("asmt_o")
    assert collapsed == 1   # only the duplicate HSTS collapses
    with isolated.session() as sess:
        kept = {f.title for f in sess.exec(__import__("sqlmodel").select(Finding)).all()
                if f.assessment_id == "asmt_o" and f.status != "duplicate"}
    assert kept == {"Missing Content-Security-Policy", "Missing HSTS",
                    "Missing X-Content-Type-Options: nosniff"}


def test_cross_identity_validates_vertical_privesc(isolated):
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    def seed(fid):
        with isolated.session() as s:
            s.add(Finding(id=fid, assessment_id="asmt_pe", title="Broken Access Control on /admin/report",
                          severity="high", status="candidate", repro_url="https://t/admin/report",
                          repro_method="GET"))
            s.commit()

    class _IdSB:
        """admin + low-priv user both read the resource (privesc); anon is denied."""
        def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
            cookie = (headers or {}).get("Cookie", "")
            if cookie in ("a", "u"):
                return {"status": 200, "headers": {}, "body": "ADMIN REPORT: revenue=... " * 6}
            return {"status": 401, "headers": {}, "body": "no"}

    ids = [{"label": "admin", "role": "admin", "headers": {"Cookie": "a"}},
           {"label": "low", "role": "user", "headers": {"Cookie": "u"}},
           {"label": "anon", "role": "anonymous", "headers": {}}]
    seed("pe1")
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_pe", sandbox=_IdSB(), emit=Emitter("asmt_pe", persist=False), identities=ids))
    assert counts["validated"] == 1
    with isolated.session() as s:
        assert "vertical" in (s.get(Finding, "pe1").validation_note or "")


def test_cross_identity_rejects_when_boundary_enforced(isolated):
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    with isolated.session() as s:
        s.add(Finding(id="pe2", assessment_id="asmt_pe2", title="IDOR on /admin/report", severity="high",
                      status="candidate", repro_url="https://t/admin/report", repro_method="GET"))
        s.commit()

    class _OnlyAdmin:
        def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=60_000):
            if (headers or {}).get("Cookie") == "a":
                return {"status": 200, "headers": {}, "body": "ADMIN REPORT " * 10}
            return {"status": 403, "headers": {}, "body": "forbidden"}

    ids = [{"label": "admin", "role": "admin", "headers": {"Cookie": "a"}},
           {"label": "low", "role": "user", "headers": {"Cookie": "u"}}]
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_pe2", sandbox=_OnlyAdmin(), emit=Emitter("asmt_pe2", persist=False), identities=ids))
    assert counts["rejected"] == 1 and counts["validated"] == 0


def test_autofiled_probe_finding_validates(isolated):
    from sqlmodel import select

    from owlforge.engine.orchestrator import _autofile_probe_finding
    from owlforge.engine.validate import validate_findings
    from owlforge.store.models import Finding

    # the pre-probe confirmed SQLi deterministically; owlforge files it itself
    _autofile_probe_finding("asmt_af", {
        "url": "https://t/catalog", "param": "category", "method": "GET",
        "payload": "'", "success_signal": "500",
        "title": "SQL injection (error-based)", "severity": "high"})
    with isolated.session() as s:
        row = s.exec(select(Finding).where(Finding.assessment_id == "asmt_af")).one()
        assert row.status == "candidate" and "auto-filed" in (row.validation_note or "")

    # validation re-issues the repro; the fake returns 500 for category=' -> validated
    counts = asyncio.run(validate_findings(
        assessment_id="asmt_af", sandbox=_FakeSandbox("err"), emit=Emitter("asmt_af", persist=False)))
    assert counts["validated"] == 1
