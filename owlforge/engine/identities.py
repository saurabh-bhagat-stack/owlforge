"""Identity / role manager — multiple authenticated sessions for one assessment.

An assessment can carry several role-labelled identities (unauth + user A + user B +
low-priv + admin). Each resolves to a set of session headers; horizontal/vertical
access-control testing (M6) compares across them. The 'sso' auth type defers to the
Auth Broker's interactive capture (M2b). TOTP is computed dependency-free (RFC 6238).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl

RequestFn = Callable[..., dict]


def totp_now(secret: str, *, for_time: float | None = None, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP (SHA-1). `secret` is base32. Dependency-free."""
    pad = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret.upper().replace(" ", "") + pad)
    counter = int((for_time if for_time is not None else time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


@dataclass
class Identity:
    label: str
    role: str = "user"
    auth: dict = field(default_factory=dict)         # {type, ...}
    session_headers: dict = field(default_factory=dict)
    needs_sso: bool = False                           # resolved by the Auth Broker (M2b)
    established: bool = False


def load_identities(path: str) -> list[Identity]:
    """Load identities from a YAML file. Always prepends an implicit unauth identity."""
    import yaml

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out = [Identity(label="unauth", role="anonymous", auth={"type": "unauth"})]
    for row in data.get("identities", []) or []:
        out.append(Identity(label=str(row.get("label") or f"id{len(out)}"),
                            role=str(row.get("role") or "user"),
                            auth=dict(row.get("auth") or {})))
    return out


def establish_identity(identity: Identity, request_fn: RequestFn,
                       log: Callable[[str], None] = lambda m: None) -> dict:
    """Resolve one identity to session headers. Returns the headers (also stored on the
    identity). 'sso' marks needs_sso for the Auth Broker and returns {} for now."""
    from owlforge.engine.auth import AuthContext, establish_session

    a = identity.auth or {}
    kind = (a.get("type") or "unauth").lower()
    headers: dict = {}

    if kind == "unauth":
        headers = {}
    elif kind == "cookie":
        headers = {"Cookie": a["cookie"]} if a.get("cookie") else {}
    elif kind == "header":
        raw = a.get("header") or ""
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers = {k.strip(): v.strip()}
    elif kind == "login":
        params = dict(parse_qsl(a.get("data") or ""))
        if a.get("totp_secret"):
            params[a.get("totp_field") or "otp"] = totp_now(a["totp_secret"])
        ctx = AuthContext(mode="login", login_url=a.get("url"), login_params=params,
                          login_success=a.get("success"))
        headers = establish_session(ctx, request_fn, log=log)
    elif kind == "sso":
        identity.needs_sso = True
        log(f"identity '{identity.label}': SSO — deferred to interactive capture")
    else:
        log(f"identity '{identity.label}': unknown auth type '{kind}'")

    identity.session_headers = headers
    identity.established = bool(headers) or kind == "unauth"
    return headers


def establish_all(identities: list[Identity], request_fn: RequestFn,
                  log: Callable[[str], None] = lambda m: None) -> list[Identity]:
    for ident in identities:
        establish_identity(ident, request_fn, log=log)
    return identities


def primary_identity(identities: list[Identity]) -> Identity | None:
    """The identity that drives authenticated recon/hunt: first with a real session
    (prefer a privileged role), else the unauth one."""
    authed = [i for i in identities if i.session_headers]
    if authed:
        authed.sort(key=lambda i: (i.role in ("admin", "superuser", "root"),), reverse=True)
        return authed[0]
    return identities[0] if identities else None
