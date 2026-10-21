"""TUI polish: compact tool-result display + consecutive-duplicate suppression."""
from __future__ import annotations

import io

from rich.console import Console

from owlforge.engine.agent import _compact_result
from owlforge.engine.events import Emitter


def test_compact_result_http():
    r = ("status=200\nfinal_url=https://x/y\n"
         "headers={'content-type': 'text/html; charset=utf-8', 'content-length': '2904'}\n"
         "body[:3000]:\n<html>")
    out = _compact_result(r)
    assert "200" in out and "text/html" in out and "2904B" in out and "https://x/y" in out
    assert "\n" not in out  # one tidy line


def test_compact_result_non_http_single_line():
    assert _compact_result("Note saved: foo") == "Note saved: foo"
    multi = _compact_result("first line\nsecond\nthird")
    assert multi.startswith("first line") and "\n" not in multi


def test_emitter_suppresses_consecutive_duplicates():
    buf = io.StringIO()
    em = Emitter("a", console=Console(file=buf, width=120, no_color=True), persist=False)
    em("status", "recon: crawled 7 page(s)")
    em("status", "recon: crawled 7 page(s)")
    em("status", "recon: crawled 7 page(s)")
    em("status", "next step")
    text = buf.getvalue()
    assert text.count("recon: crawled 7 page(s)") == 1      # printed once, not 3x
    assert "repeated x2 more" in text                        # with a collapse notice
    assert "next step" in text


def test_banner_renders_wordmark():
    import io

    from rich.console import Console

    import owlforge.cli as cli
    from owlforge import __version__
    buf = io.StringIO()
    cli.console = Console(file=buf, width=80, no_color=True)
    cli._banner()
    out = buf.getvalue()
    assert __version__ in out and "penetration testing" in out  # wordmark art + subtitle
