"""P0 #1: content-type / POST-body probing + in-band XXE + repro mapping."""

from __future__ import annotations

from owlforge.engine.classify import SQLI, XXE
from owlforge.engine.preprobe import probe


class _SB:
    """Fake sandbox that records how each request was issued (query vs body)."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def http_request(self, method, url, *, headers=None, params=None, body=None, timeout_ms=30_000):
        self.calls.append({"method": method, "params": params, "body": body,
                           "ct": (headers or {}).get("Content-Type")})
        return self._responder(params, body)


def test_post_param_payload_goes_in_body_not_query():
    # error-based SQLi, but the param is a POST body field
    def responder(params, body):
        # the quote injection must arrive in the BODY to trigger the 500
        if body and "%27" in body:          # url-encoded single quote
            return {"status": 500, "body": ""}
        return {"status": 200, "body": "ok"}

    sb = _SB(responder)
    sig, note, repro = probe(SQLI, {"url": "https://t/api/search", "param": "q",
                                    "method": "POST"}, sb)
    assert sig is True and repro is not None
    assert repro["where"] == "body"
    assert repro["content_type"] == "application/x-www-form-urlencoded"
    # the payload was sent in the body, never as a query param
    assert all(c["params"] is None for c in sb.calls)
    assert any(c["body"] and "%27" in c["body"] for c in sb.calls)
    assert all(c["ct"] == "application/x-www-form-urlencoded" for c in sb.calls)


def test_get_param_still_uses_query():
    def responder(params, body):
        if params and params.get("q") == "1'":
            return {"status": 500, "body": ""}
        return {"status": 200, "body": "ok"}

    sb = _SB(responder)
    sig, _n, repro = probe(SQLI, {"url": "https://t/search", "param": "q", "method": "GET"}, sb)
    assert sig is True
    assert "where" not in repro  # query payload -> no body marker
    assert all(c["body"] is None for c in sb.calls)


def test_xxe_inband_probe_detects_etc_passwd():
    def responder(params, body):
        if body and "file:///etc/passwd" in body:
            return {"status": 200, "body": "stock: root:x:0:0:root:/root:/bin/bash"}
        return {"status": 200, "body": "stock: 42"}

    sb = _SB(responder)
    sig, note, repro = probe(XXE, {"url": "https://t/stock", "param": None, "method": "POST"}, sb)
    assert sig is True and repro is not None
    assert repro["title"].startswith("XML external entity")
    assert repro["content_type"] == "application/xml"
    assert repro["success_signal"] == "root:x:0:0"
    assert sb.calls and sb.calls[0]["ct"] == "application/xml"


def test_xxe_negative_when_not_resolved():
    sb = _SB(lambda params, body: {"status": 200, "body": "stock: 42"})
    sig, _n, repro = probe(XXE, {"url": "https://t/stock", "param": None, "method": "POST"}, sb)
    assert sig is False and repro is None


def test_repro_location_maps_body_vs_query():
    from owlforge.engine.orchestrator import _repro_location
    body_rep = {"param": "q", "payload": "1'", "where": "body",
                "content_type": "application/x-www-form-urlencoded"}
    loc = _repro_location(body_rep)
    assert loc["repro_body"] == "q=1%27" and loc["repro_params"] == {}
    assert loc["repro_content_type"] == "application/x-www-form-urlencoded"

    xml_rep = {"param": "(xml body)", "payload": "<r/>", "where": "body",
               "content_type": "application/xml"}
    loc = _repro_location(xml_rep)
    assert loc["repro_body"] == "<r/>" and loc["repro_content_type"] == "application/xml"

    query_rep = {"param": "q", "payload": "1'"}
    loc = _repro_location(query_rep)
    assert loc["repro_params"] == {"q": "1'"} and loc["repro_body"] == ""
