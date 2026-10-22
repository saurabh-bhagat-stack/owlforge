"""App model — owlforge's structural understanding of the target.

Before hunting logic flaws, a human tester forms a mental model of the application: what
ENTITIES it manages (users, posts, orders), what ACTIONS exist over them (register, create,
edit, delete, approve, upload, pay), which ACTORS (roles) are in play, and how actions chain
into WORKFLOWS (create -> submit -> approve -> publish). Parameter fuzzing can't see any of
this; the model can, so the scenario engine (scenarios.py) reasons over it to generate and
rank business-logic / authorization hypotheses instead of only mutating parameters.

This module is pure extraction — no network, no LLM. It reads the mapped surface (the
blackboard), the identities, and the seeded-object URLs, and returns an AppModel. Building
the model is cheap and deterministic; acting on it is the scenario engine's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---- action kinds -----------------------------------------------------------------------
REGISTER = "register"
LOGIN = "login"
LOGOUT = "logout"
CREATE = "create"
EDIT = "edit"
DELETE = "delete"
UPLOAD = "upload"
TRANSITION = "transition"   # approve / publish / checkout / pay / confirm / cancel …
READ = "read"

_REG_HINT = ("register", "signup", "sign-up", "sign_up", "/join", "create-account",
             "createaccount", "users/new", "accounts/new", "registration")
_LOGIN_HINT = ("login", "signin", "sign-in", "sign_in", "/auth", "sessions")
_LOGOUT_HINT = ("logout", "signout", "sign-out", "sign_out")
_PASS_HINT = ("password", "passwd", "pwd", "pass")
_FILE_HINT = ("file", "upload", "attachment", "avatar", "document", "photo", "image", "userfile")
_CREATE_HINT = ("create", "/new", "/add", "compose", "/post", "store", "/save", "submit-")
_EDIT_HINT = ("edit", "update", "/modify", "settings", "profile", "/account")
_DELETE_HINT = ("delete", "remove", "destroy", "/del", "trash")
_TRANSITION_HINT = ("approve", "publish", "confirm", "checkout", "/pay", "payment", "cancel",
                    "complete", "activate", "verify", "promote", "accept", "reject",
                    "deactivate", "finalize", "settle", "refund", "ship", "fulfill",
                    "/submit", "redeem", "apply-coupon", "validate", "escalate")
_PRIV_ROLE = ("admin", "root", "superuser", "super-user", "staff", "manager", "owner",
              "operator", "moderator", "god")

# order used when rendering an entity's workflow
_WF_ORDER = [CREATE, UPLOAD, EDIT, TRANSITION, DELETE]


@dataclass
class Action:
    kind: str
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    entity: str = ""


@dataclass
class Entity:
    name: str
    instances: list[str] = field(default_factory=list)   # seeded / observed object URLs
    actions: list[Action] = field(default_factory=list)


@dataclass
class Role:
    label: str
    role: str = "user"
    headers: dict = field(default_factory=dict)
    privileged: bool = False


@dataclass
class Workflow:
    name: str
    steps: list[str]        # ordered action kinds


@dataclass
class AppModel:
    entities: list[Entity] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    workflows: list[Workflow] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)

    # -- convenience views the scenario engine uses --------------------------------------
    def actions_of(self, *kinds: str) -> list[Action]:
        return [a for a in self.actions if a.kind in kinds]

    def privileged_roles(self) -> list[Role]:
        return [r for r in self.roles if r.privileged]

    def has_transitions(self) -> bool:
        return any(a.kind == TRANSITION for a in self.actions)

    def is_interesting(self) -> bool:
        """Worth the scenario engine's (and an LLM specialist's) time?"""
        return bool(self.actions_of(CREATE, EDIT, UPLOAD, TRANSITION)
                    or len(self.privileged_roles()) >= 1
                    or len([r for r in self.roles if r.headers]) >= 2)

    def summary(self) -> str:
        """A compact human/LLM-readable model."""
        lines: list[str] = []
        if self.entities:
            lines.append("Entities:")
            for e in self.entities[:12]:
                kinds = ", ".join(sorted({a.kind for a in e.actions})) or "read"
                inst = f" ({len(e.instances)} seeded)" if e.instances else ""
                lines.append(f"  - {e.name}{inst}: {kinds}")
        if self.roles:
            lines.append("Actors/roles:")
            for r in self.roles:
                tag = " [privileged]" if r.privileged else (" [session]" if r.headers else "")
                lines.append(f"  - {r.label} (role={r.role}){tag}")
        if self.workflows:
            lines.append("Workflows:")
            for w in self.workflows[:10]:
                lines.append(f"  - {w.name}: {' -> '.join(w.steps)}")
        if self.tech:
            lines.append("Tech: " + ", ".join(self.tech))
        return "\n".join(lines) if lines else "(no structured model extracted)"


# ---- classification ---------------------------------------------------------------------
_SEG = re.compile(r"/([A-Za-z][A-Za-z0-9_-]*)")


def _has(text: str, hints) -> bool:
    return any(h in text for h in hints)


def _singular(seg: str) -> str:
    s = seg.lower()
    if s.endswith("ies") and len(s) > 3:
        return s[:-3] + "y"
    if s.endswith("ses") and len(s) > 3:
        return s[:-2]
    if s.endswith("s") and not s.endswith("ss") and len(s) > 3:
        return s[:-1]
    return s


_NON_ENTITY = {"api", "v1", "v2", "v3", "app", "www", "public", "static", "assets", "new",
               "edit", "create", "add", "delete", "remove", "update", "index", "home",
               "login", "logout", "signin", "signup", "register", "auth", "account",
               "admin", "dashboard", "search", "about", "contact", "help", "settings"}


def _entity_of(url: str) -> str:
    """Best-guess entity name from a URL path: the resource segment before an id/verb."""
    path = url.split("://", 1)[-1]
    path = path.split("/", 1)[1] if "/" in path else ""
    path = path.split("?", 1)[0]
    segs = [s for s in _SEG.findall("/" + path)]
    best = ""
    for i, seg in enumerate(segs):
        low = seg.lower()
        if low in _NON_ENTITY:
            continue
        # a resource segment is typically followed by an id, a verb, or nothing
        nxt = segs[i + 1] if i + 1 < len(segs) else ""
        if (not nxt or re.fullmatch(r"\d+", nxt) or re.fullmatch(r"[0-9a-f-]{8,}", nxt)
                or nxt.lower() in _NON_ENTITY or nxt.lower() in _EDIT_HINT_SEG):
            best = low
            break
        if not best:
            best = low
    return _singular(best) if best else ""


_EDIT_HINT_SEG = {"edit", "update", "modify", "delete", "remove", "approve", "publish",
                  "confirm", "checkout", "pay", "cancel", "complete", "submit"}


def classify_action(url: str, method: str, params: list[str]) -> str:
    low = url.lower()
    pblob = " ".join(p.lower() for p in (params or []))
    m = (method or "GET").upper()
    has_pass = _has(pblob, _PASS_HINT)
    if _has(low, _LOGOUT_HINT):
        return LOGOUT
    if (_has(low, _REG_HINT) and has_pass) or (has_pass and ("confirm" in pblob or "repeat" in pblob)):
        return REGISTER
    if _has(low, _LOGIN_HINT) and has_pass:
        return LOGIN
    if any(f in pblob.split() or any(f in p for p in (params or [])) for f in _FILE_HINT) \
            or _has(low, ("upload",)):
        return UPLOAD
    if _has(low, _TRANSITION_HINT) or _has(pblob, _TRANSITION_HINT):
        return TRANSITION
    if m == "DELETE" or _has(low, _DELETE_HINT):
        return DELETE
    if _has(low, _EDIT_HINT) or m in ("PUT", "PATCH"):
        return EDIT
    if m == "POST" and (_has(low, _CREATE_HINT) or True):
        return CREATE
    return READ


def build_app_model(inventory: list[dict], identities: list[dict] | None = None,
                    seeded_urls=(), tech=()) -> AppModel:
    """Build the structural model from the mapped surface, identities and seeded objects.

    `inventory` is read_blackboard() output (url/method/params/source). `identities` are the
    {label, role, headers} dicts the pipeline already carries. `seeded_urls` are the URLs of
    objects owlforge created during seeding (SurfaceItem source='seeded')."""
    actions: list[Action] = []
    ents: dict[str, Entity] = {}

    for it in inventory or []:
        url = it.get("url") or ""
        if not url:
            continue
        method = (it.get("method") or "GET").upper()
        params = list(it.get("params") or [])
        # only state-changing items or clearly interesting reads become actions
        kind = classify_action(url, method, params)
        ename = _entity_of(url)
        if method in ("POST", "PUT", "PATCH", "DELETE") or kind in (
                REGISTER, LOGIN, LOGOUT, TRANSITION):
            act = Action(kind=kind, url=url, method=method, params=params, entity=ename)
            actions.append(act)
            if ename:
                ents.setdefault(ename, Entity(name=ename)).actions.append(act)
        elif ename and ename not in _NON_ENTITY:
            ents.setdefault(ename, Entity(name=ename))

    for u in seeded_urls or []:
        en = _entity_of(u)
        if en:
            ents.setdefault(en, Entity(name=en)).instances.append(u)

    # roles
    roles: list[Role] = []
    seen_lbl = set()
    for idn in identities or []:
        lbl = idn.get("label") or "actor"
        if lbl in seen_lbl:
            continue
        seen_lbl.add(lbl)
        role = (idn.get("role") or "user").lower()
        priv = _has(lbl.lower(), _PRIV_ROLE) or _has(role, _PRIV_ROLE)
        roles.append(Role(label=lbl, role=role, headers=idn.get("headers") or {}, privileged=priv))

    # workflows: a global auth flow + a per-entity lifecycle
    workflows: list[Workflow] = []
    auth_steps = [k for k in (REGISTER, LOGIN, LOGOUT) if any(a.kind == k for a in actions)]
    if auth_steps:
        workflows.append(Workflow(name="authentication", steps=auth_steps))
    for name, e in ents.items():
        kinds = {a.kind for a in e.actions}
        steps = [k for k in _WF_ORDER if k in kinds]
        if len(steps) >= 2:
            workflows.append(Workflow(name=f"{name} lifecycle", steps=steps))

    # prune noise entities (no actions and no instances)
    entities = [e for e in ents.values() if e.actions or e.instances]
    entities.sort(key=lambda e: (-len(e.actions), -len(e.instances), e.name))

    return AppModel(entities=entities, actions=actions, roles=roles,
                    workflows=workflows, tech=list(tech or []))
