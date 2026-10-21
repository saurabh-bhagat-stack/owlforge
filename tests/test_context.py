"""Context auto-detect for cloud/frontier + OpenAI-compatible endpoints."""
from __future__ import annotations

from types import SimpleNamespace


def test_known_context_map():
    from owlforge.llm.client import _known_context
    assert _known_context("gpt-4o-2024") == 128000
    assert _known_context("claude-opus-4-8") == 200000
    assert _known_context("glm-4.7-flash") == 131072
    assert _known_context("totally-unknown-model") is None


def test_openai_models_reports_context(monkeypatch):
    import owlforge.llm.client as c

    def fake_get(url, timeout=5.0):
        return SimpleNamespace(status_code=200, json=lambda: {
            "data": [{"id": "my-model", "max_model_len": 40960}]})
    import httpx
    monkeypatch.setattr(httpx, "get", fake_get)
    assert c._openai_models_context("http://x/v1", "my-model") == 40960


def test_llamacpp_props(monkeypatch):
    import httpx

    import owlforge.llm.client as c

    def fake_get(url, timeout=5.0):
        assert url.endswith("/props")
        return SimpleNamespace(status_code=200,
                               json=lambda: {"default_generation_settings": {"n_ctx": 32768}})
    monkeypatch.setattr(httpx, "get", fake_get)
    assert c._llamacpp_props_context("http://x/v1") == 32768


def test_detect_falls_back_to_known(monkeypatch):
    import httpx

    import owlforge.llm.client as c
    def boom(*a, **k):
        raise RuntimeError("no server")
    monkeypatch.setattr(httpx, "post", boom)
    monkeypatch.setattr(httpx, "get", boom)
    assert c.detect_context_window("http://x/v1", "gpt-4o") == 128000
