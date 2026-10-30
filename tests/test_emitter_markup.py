"""Regression: the console Emitter must not choke on target/model text that contains square
brackets (Rich markup). A stray '[/conf_password]' in a status line once crashed whole runs and
masked the real error."""
from __future__ import annotations

import io

from rich.console import Console

from owlforge.engine.events import Emitter


def _emit_to_string(type_, message):
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=False, width=200)
    e = Emitter("a1", console=con, persist=False)
    e(type_, message)                    # must not raise
    return buf.getvalue()


def test_bracketed_message_does_not_crash():
    out = _emit_to_string("status", "surface params: [/conf_password] and [red]x[/]")
    assert "conf_password" in out
    assert "STATUS" in out


def test_unbalanced_markup_tag_is_safe():
    # the exact shape that crashed: a lone closing tag
    out = _emit_to_string("log", "payload rejected: [/conf_password]")
    assert "conf_password" in out


def test_normal_message_still_renders():
    out = _emit_to_string("status", "recon: crawled 3 pages")
    assert "recon: crawled 3 pages" in out
