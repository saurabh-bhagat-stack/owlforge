"""Ingest an API description as a scan target.

owlforge already auto-discovers an OpenAPI/Swagger spec served by the target during recon.
This module lets the operator point owlforge straight at a spec they already hold —
`owlforge run ./openapi.yaml` or `owlforge run ./postman_collection.json` — deriving the
base URL from the document and turning every operation into a surface item so the whole
API is tested without crawling. Supports OpenAPI 3, Swagger 2, and Postman v2.x
collections, in JSON or YAML. Parsing only (json/yaml.safe_load) — nothing is executed.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

import yaml

_SPEC_EXT = (".json", ".yaml", ".yml")
_METHODS = ("get", "post", "put", "patch", "delete")


def looks_like_spec_file(target: str) -> bool:
    """True when the target is a local file we should parse as an API description."""
    if not target:
        return False
    p = os.path.expanduser(target)
    return os.path.isfile(p) and p.lower().endswith(_SPEC_EXT)


def _parse(text: str) -> dict:
    text = text.strip()
    try:
        data = json.loads(text)
    except Exception:
        data = yaml.safe_load(text)  # YAML is a JSON superset; handles both
    if not isinstance(data, dict):
        raise ValueError("spec is not a JSON/YAML object")
    return data


# ---- OpenAPI / Swagger -----------------------------------------------------------------
def openapi_base(spec: dict, hint: str = "") -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = str(servers[0].get("url", "")).strip()
        if u.startswith("http"):
            return u.rstrip("/")
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath", "") or ""
        return f"{scheme}://{host}{base_path}".rstrip("/")
    return (hint or "").rstrip("/")


def openapi_to_items(spec: dict, base_url: str) -> list[dict]:
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        return []
    origin = base_url.rstrip("/")
    out = []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if str(method).lower() not in _METHODS:
                continue
            params = []
            if isinstance(op, dict):
                for pr in op.get("parameters", []) or []:
                    if isinstance(pr, dict) and pr.get("name"):
                        params.append(str(pr["name"]))
            # truncate at the first path-template segment (consistent with recon discovery)
            clean = origin + ("/" + str(path).lstrip("/")).split("{")[0].rstrip("/")
            out.append({"url": clean or origin + "/" + str(path).lstrip("/"),
                        "method": str(method).upper(), "params": sorted(set(params)),
                        "source": "api-spec"})
    return out


# ---- Postman ---------------------------------------------------------------------------
def _postman_vars(coll: dict) -> dict:
    out = {}
    for v in coll.get("variable", []) or []:
        if isinstance(v, dict) and v.get("key") is not None:
            out[str(v["key"])] = str(v.get("value", ""))
    return out


def _subst(raw: str, vars_: dict) -> str:
    def repl(m):
        return vars_.get(m.group(1), m.group(0))
    return re.sub(r"\{\{\s*([^}]+?)\s*\}\}", repl, raw or "")


def postman_to_items(coll: dict) -> tuple[str, list[dict]]:
    vars_ = _postman_vars(coll)
    base = ""
    items: list[dict] = []

    def _raw_url(url) -> tuple[str, list[str]]:
        params: list[str] = []
        if isinstance(url, str):
            return url, params
        if isinstance(url, dict):
            for q in url.get("query", []) or []:
                if isinstance(q, dict) and q.get("key"):
                    params.append(str(q["key"]))
            raw = url.get("raw")
            if raw:
                return str(raw), params
            host = url.get("host")
            host_s = ".".join(host) if isinstance(host, list) else str(host or "")
            path = url.get("path")
            path_s = "/".join(str(x) for x in path) if isinstance(path, list) else str(path or "")
            return f"{host_s}/{path_s}", params
        return "", params

    def walk(node: dict) -> None:
        nonlocal base
        for it in node.get("item", []) or []:
            if isinstance(it, dict) and "item" in it:
                walk(it)
                continue
            req = it.get("request") if isinstance(it, dict) else None
            if not isinstance(req, dict):
                continue
            method = str(req.get("method", "GET")).upper()
            raw, params = _raw_url(req.get("url"))
            raw = _subst(raw, vars_).split("?")[0].strip()
            if not raw:
                continue
            if "://" not in raw and base:
                raw = base.rstrip("/") + "/" + raw.lstrip("/")
            if "://" in raw and not base:
                sp = urlsplit(raw)
                base = f"{sp.scheme}://{sp.netloc}"
            if "://" not in raw:
                continue
            items.append({"url": raw, "method": method,
                          "params": sorted(set(params)), "source": "api-spec"})

    walk(coll)
    return base, items


# ---- entry point -----------------------------------------------------------------------
def ingest_spec(source: str) -> tuple[str, list[dict], str]:
    """Parse a spec file (path) and return (base_url, surface_items, kind)."""
    path = os.path.expanduser(source)
    with open(path, encoding="utf-8", errors="replace") as f:
        data = _parse(f.read())
    if "openapi" in data or "swagger" in data:
        base = openapi_base(data)
        return base, openapi_to_items(data, base), "openapi"
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    schema = str((info or {}).get("schema", "")).lower()
    if "item" in data or "postman" in schema or "getpostman" in schema:
        base, items = postman_to_items(data)
        return base, items, "postman"
    raise ValueError("unrecognised API description (expected OpenAPI/Swagger or Postman)")
