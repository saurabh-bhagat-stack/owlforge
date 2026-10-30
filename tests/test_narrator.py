"""Shared narrator: renderer-agnostic narration, hygiene detection, transcript, and the Emitter's
hygiene folding — so the stream, the TUI and the web console tell the same story."""
from __future__ import annotations

import io

from rich.console import Console

from owlforge.engine import narrator
from owlforge.engine.events import Emitter
from owlforge.engine.narrator import NarratedLine, is_hygiene, narrate, phase_of


def test_narrate_rewrites_recon():
    line = narrate("status", "recon: crawled 5 page(s), 4 surface item(s)")
    assert line and "crawled the site" in line.body and line.tag.strip() == "recon"


def test_narrate_api_surface_and_auth():
    assert "mined the JS bundle" in narrate("status", "api-surface: recovered 30 endpoints").body
    a = narrate("status", "auth: operating with 2 authenticated identities")
    assert a.tag.strip() == "auth OK"


def test_hygiene_detection():
    assert is_hygiene("Missing Content-Security-Policy")
    assert is_hygiene("Clickjacking: no X-Frame-Options")
    assert is_hygiene("Cookie without HttpOnly flag: session")
    assert not is_hygiene("Broken object-level authorization (BOLA)")
    assert not is_hygiene("SQL injection in id parameter")


def test_finding_carries_hygiene_flag():
    h = narrate("finding", "candidate filed: Missing X-Content-Type-Options")
    r = narrate("finding_validated", "VALIDATED: BOLA at /api/v2/vehicle/{id}")
    assert h.kind == "finding" and h.hygiene is True
    assert r.kind == "finding" and r.hygiene is False


def test_think_and_tool_and_skip():
    assert narrate("think", "the login 404s").kind == "think"
    assert narrate("tool_call", "http_request GET http://t/api/x").kind == "http"
    assert narrate("assistant", "chatty filler") is None      # noise is dropped


def test_phase_of():
    assert phase_of("[specialist:sqli] testing") == "hunt"
    assert phase_of("access-control: testing") == "deterministic passes"
    assert phase_of("reporting phase") == "reporting"


def test_transcript_writes_file(tmp_path, monkeypatch):
    import owlforge.config as config
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    t = narrator.Transcript("asmt-x")
    t.write(NarratedLine(tag="recon  ", body="crawled the site", kind="activity"), phase="recon")
    t.write(NarratedLine(tag="confirmed  ", body="BOLA found", kind="finding"), phase="deterministic passes")
    assert t.path is not None
    txt = t.path.read_text()
    assert "## recon" in txt and "crawled the site" in txt and "BOLA found" in txt


def test_emitter_folds_hygiene_into_one_notice(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    buf = io.StringIO()
    e = Emitter("asmt-y", console=Console(file=buf, force_terminal=False, width=100), persist=True)
    for msg in ("Missing Content-Security-Policy", "Clickjacking: no X-Frame-Options",
                "Missing X-Content-Type-Options", "Version disclosure via server"):
        e("finding", f"candidate filed: {msg}")
    out = buf.getvalue()
    assert out.count("security hygiene") == 1          # 4 hygiene findings -> ONE notice
    assert "Clickjacking" not in out                    # individual ones suppressed from the stream
    # but the transcript still records them for the operator
    assert e._transcript and e._transcript.path.exists()
