"""Live web console: serves the page and streams narrated events over SSE (history replay + live),
carrying the narrator's kind/hygiene/color so the browser can filter and group."""
from __future__ import annotations

import json
import threading
import time
import urllib.request

from owlforge.engine.narrator import narrate
from owlforge.engine.webui import WebConsole


def test_serves_page_and_streams_events():
    wc = WebConsole("aid", "http://t:8888", "beam:cloud")
    try:
        # events pushed before any client connects must replay from history
        for t, m in [("status", "recon: crawled 5 page(s)"),
                     ("finding_validated", "VALIDATED: BOLA at /identity/api/v2/vehicle/{id}"),
                     ("finding", "candidate filed: Missing Content-Security-Policy")]:
            wc.push(t, m, narrate(t, m))

        page = urllib.request.urlopen(wc.url(), timeout=5).read().decode()
        assert "owlforge console" in page
        assert "EventSource('/events')" in page
        assert "beam:cloud" in page            # meta injected

        got = []
        req = urllib.request.urlopen(wc.url() + "events", timeout=5)
        threading.Thread(
            target=lambda: (time.sleep(0.3), wc.push("think", "the login 404s",
                                                      narrate("think", "the login 404s"))),
            daemon=True).start()
        start = time.time()
        while time.time() - start < 3 and len(got) < 4:
            line = req.readline()
            if line.startswith(b"data: "):
                got.append(json.loads(line[6:]))
        assert len(got) == 4                   # 3 replayed + 1 live
        kinds = {e["kind"] for e in got}
        assert "finding" in kinds and "think" in kinds
        hyg = next(e for e in got if "Content-Security-Policy" in e["body"])
        assert hyg["hygiene"] is True          # hygiene flag carried for client-side folding
        val = next(e for e in got if "BOLA" in e["body"])
        assert val["color"] == "green"         # validated finding color mapping
    finally:
        wc.stop()


def test_url_is_localhost():
    wc = WebConsole("aid2", "http://t", "m")
    try:
        assert wc.url().startswith("http://127.0.0.1:")
    finally:
        wc.stop()
