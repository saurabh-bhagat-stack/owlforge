"""API-description ingestion: OpenAPI 3 / Swagger 2 (JSON+YAML) and Postman."""
from __future__ import annotations

import json

from owlforge.engine.apispec import (
    ingest_spec,
    looks_like_spec_file,
    openapi_base,
    openapi_to_items,
    postman_to_items,
)


def test_openapi3_base_and_items():
    oas = {"openapi": "3.0.0", "servers": [{"url": "https://api.ex.com/v1"}],
           "paths": {"/users/{id}": {"get": {"parameters": [{"name": "id"}, {"name": "fields"}]}},
                     "/search": {"get": {"parameters": [{"name": "q"}]}}}}
    base = openapi_base(oas)
    assert base == "https://api.ex.com/v1"
    items = openapi_to_items(oas, base)
    urls = {(i["method"], i["url"]) for i in items}
    assert ("GET", "https://api.ex.com/v1/users") in urls   # truncated at {id}
    assert ("GET", "https://api.ex.com/v1/search") in urls
    search = next(i for i in items if i["url"].endswith("/search"))
    assert search["params"] == ["q"] and search["source"] == "api-spec"


def test_swagger2_base_from_host():
    sw = {"swagger": "2.0", "host": "h.ex.com", "basePath": "/api", "schemes": ["https"],
          "paths": {"/items": {"post": {}}}}
    assert openapi_base(sw) == "https://h.ex.com/api"


def test_postman_vars_folders_and_query():
    pm = {"info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
          "variable": [{"key": "baseUrl", "value": "https://p.ex.com"}],
          "item": [{"name": "folder", "item": [
                       {"request": {"method": "POST",
                                    "url": {"raw": "{{baseUrl}}/login", "query": [{"key": "next"}]}}}]},
                   {"request": {"method": "GET", "url": {"raw": "{{baseUrl}}/me"}}}]}
    base, items = postman_to_items(pm)
    assert base == "https://p.ex.com"
    byurl = {i["url"]: i for i in items}
    assert "https://p.ex.com/login" in byurl and byurl["https://p.ex.com/login"]["method"] == "POST"
    assert byurl["https://p.ex.com/login"]["params"] == ["next"]
    assert "https://p.ex.com/me" in byurl


def test_ingest_detects_kind(tmp_path):
    oas = tmp_path / "openapi.json"
    oas.write_text(json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://a.test"}],
                               "paths": {"/x": {"get": {}}}}))
    base, items, kind = ingest_spec(str(oas))
    assert kind == "openapi" and base == "https://a.test" and len(items) == 1

    pm = tmp_path / "coll.json"
    pm.write_text(json.dumps({"info": {"schema": "postman"}, "item": [
        {"request": {"method": "GET", "url": {"raw": "https://b.test/ping"}}}]}))
    base, items, kind = ingest_spec(str(pm))
    assert kind == "postman" and base == "https://b.test"


def test_ingest_yaml_openapi(tmp_path):
    y = tmp_path / "api.yaml"
    y.write_text("openapi: 3.0.0\nservers:\n  - url: https://y.test\npaths:\n  /z:\n    get: {}\n")
    base, items, kind = ingest_spec(str(y))
    assert kind == "openapi" and base == "https://y.test" and items[0]["url"] == "https://y.test/z"


def test_looks_like_spec_file(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("{}")
    assert looks_like_spec_file(str(f)) is True
    assert looks_like_spec_file("https://example.com") is False
    assert looks_like_spec_file("example.com") is False
    assert looks_like_spec_file(str(tmp_path / "missing.yaml")) is False  # not a file
