"""Transport: WS/SignalR/Blazor detection + WebSocket echo pass."""

from __future__ import annotations

from owlforge.engine.transport import detect_transport, ws_surface_items


def test_detect_transport():
    ws, flags = detect_transport(
        "https://t/", 'new WebSocket("wss://t/chat"); conn.start("/hub/notify"); blazor.boot.json _blazor')
    assert "wss://t/chat" in ws and "https://t/hub/notify" in ws
    assert {"websocket", "signalr", "blazor-wasm", "blazor-server"} <= flags
    items = ws_surface_items(ws)
    assert all(i["method"] == "WS" and i["source"] == "websocket" for i in items)


def test_ws_scan_flags_echo(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()

    from sqlmodel import select

    from owlforge.engine.wsprobe import ws_scan
    from owlforge.store.models import Finding

    class _SB:
        def ws_probe(self, url, *, messages=None, headers=None, timeout_ms=8000):
            # echo the first marker back
            return {"connected": True, "error": "", "responses": [messages[0] if messages else ""]}

    inv = [{"url": "wss://t/chat", "method": "WS", "params": ["message"], "source": "websocket"}]
    n = ws_scan("asmt_ws", inv, _SB())
    assert n == 1
    with db.session() as s:
        f = s.exec(select(Finding).where(Finding.assessment_id == "asmt_ws")).one()
    assert "WebSocket reflects" in f.title
