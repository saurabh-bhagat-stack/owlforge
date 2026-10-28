"""owlforge command-line interface."""

from __future__ import annotations

import secrets
from datetime import UTC

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlmodel import select

from owlforge import __version__
from owlforge.config import (
    assessments_dir,
    config_path,
    load_config,
    owlforge_home,
    write_default_config,
)
from owlforge.engine.events import Emitter
from owlforge.engine.validate import validate_findings
from owlforge.llm.client import LLMError, make_client
from owlforge.report.builder import build_and_save_report
from owlforge.sandbox import manager
from owlforge.store.db import init_db, session
from owlforge.store.models import Assessment, Finding, Report

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="owlforge — local-first autonomous agentic pentest platform.",
)
assessments_app = typer.Typer(no_args_is_help=True, help="Inspect assessments.")
sandbox_app = typer.Typer(no_args_is_help=True, help="Manage the sandbox image.")
app.add_typer(assessments_app, name="assessments")
app.add_typer(sandbox_app, name="sandbox")

console = Console()

_SEV_RANKS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _maybe_update_image(image: str, *, pull: bool, no_pull: bool, interactive: bool) -> None:
    """Best-effort sandbox-image freshness check. Never blocks a scan: skips silently
    for local builds / offline / registry errors. --no-pull skips; --pull always pulls;
    otherwise an interactive run prompts (default N) when a newer image exists, and a
    headless run just prints a one-line notice."""
    _slog = lambda m: console.print(rf"[dim]\[sandbox] {m}[/]")  # noqa: E731
    if no_pull:
        return
    if pull:
        manager.pull_image(image, log=_slog)
        return
    try:
        avail = manager.update_available(image)
    except Exception:
        return
    if not avail:  # False or None -> nothing to do
        return
    if not interactive:
        console.print(rf"[yellow]\[sandbox] a newer image is available for {image}; "
                      "re-run with --pull to update (using the current image).[/]")
        return
    console.print(r"[yellow]\[sandbox] a newer sandbox image is available.[/]")
    ans = typer.prompt("Pull the latest image now? [y/N]", default="n", show_default=False)
    if str(ans).strip().lower() in ("y", "yes"):
        manager.pull_image(image, log=_slog)
    else:
        console.print(r"[dim]\[sandbox] using the current image[/]")


def _meets_fail_threshold(validated_severities, fail_on) -> bool | None:
    """True if any validated severity is at/above fail_on; None if fail_on is
    unset or unknown (caller treats None as 'do not gate')."""
    if not fail_on:
        return None
    threshold = _SEV_RANKS.get(str(fail_on).strip().lower())
    if threshold is None:
        return None
    worst = max((_SEV_RANKS.get((x or "").lower(), 0) for x in validated_severities),
                default=-1)
    return worst >= threshold


_WORDMARK = r"""
 ██████╗ ██╗    ██╗██╗     ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔═══██╗██║    ██║██║     ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║ █╗ ██║██║     █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██║   ██║██║███╗██║██║     ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
╚██████╔╝╚███╔███╔╝███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"""


def _banner() -> None:
    """Splash shown when a scan launches."""
    from rich.text import Text
    console.print(Text(_WORDMARK, style="bold cyan"), highlight=False)
    sub = Text()
    sub.append("  ,___,  ", style="yellow")
    sub.append("autonomous web-app penetration testing", style="white")
    sub.append("   v" + __version__, style="dim")
    tag = Text()
    tag.append("  (o,o)  ", style="yellow")
    tag.append("local-first", style="green")
    tag.append(" · ", style="dim")
    tag.append("model-agnostic", style="green")
    tag.append(" · ", style="dim")
    tag.append("evidence-gated", style="green")
    console.print(sub)
    console.print(tag)
    console.print()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(5)}"


@app.command()
def version() -> None:
    """Print the owlforge version."""
    console.print(f"owlforge [bold cyan]{__version__}[/]")


@app.command()
def init() -> None:
    """Write the default config and initialize the local store."""
    path = write_default_config()
    init_db()
    console.print(
        Panel.fit(
            f"owlforge home: [bold]{owlforge_home()}[/]\n"
            f"config:        [bold]{path}[/]\n"
            f"database:      initialized",
            title="initialized",
            border_style="green",
        )
    )
    console.print("[dim]Set your local model in the config's [llm] model field.[/]")


@app.command()
def doctor() -> None:
    """Preflight: check the container engine, sandbox image, config, and model endpoint."""
    import sys

    from owlforge.config import config_path
    ok = True

    def line(status: str, label: str, detail: str = "", fix: str = "") -> None:
        icon = {"ok": "[green]✓[/]", "warn": "[yellow]![/]", "fail": "[red]✗[/]"}[status]
        console.print(f"  {icon} {label}" + (f"   [dim]{detail}[/]" if detail else ""))
        if fix:
            console.print(f"      [dim]→ {fix}[/]")

    console.print("[bold]owlforge doctor[/]\n")
    pv = sys.version_info
    if pv >= (3, 11):
        line("ok", "Python", f"{pv.major}.{pv.minor}.{pv.micro}")
    else:
        line("fail", "Python", f"{pv.major}.{pv.minor}", "need Python 3.11+")
        ok = False

    cp = config_path()
    if cp.exists():
        line("ok", "Config", str(cp))
    else:
        line("warn", "Config", "not initialized", "run `owlforge init`")
    cfg = load_config()

    eng = manager.container_engine()
    ver = manager.engine_version(eng)
    running = manager.docker_available()
    if ver is None:
        line("fail", "Container engine", f"`{eng}` not found on PATH",
             "install Docker Desktop / colima / Rancher Desktop / Podman")
        ok = False
    elif not running:
        line("fail", "Container engine", f"`{eng}` {ver} installed but not running",
             manager.engine_start_hint(eng))
        ok = False
    else:
        line("ok", "Container engine", f"`{eng}` {ver} running")

    if running:
        if manager.image_exists(cfg.sandbox.image):
            line("ok", "Sandbox image", "present")
        else:
            line("warn", "Sandbox image", "not pulled yet",
                 "`owlforge sandbox pull` (or it auto-pulls on the first run)")
    else:
        line("warn", "Sandbox image", "(skipped — engine not running)")

    base, model = cfg.llm.base_url, cfg.llm.model
    if not base or not model:
        line("warn", "LLM endpoint", "not configured", f"set [llm] base_url + model in {cp}")
    else:
        reachable = False
        try:
            import httpx
            httpx.get(base.rstrip("/").removesuffix("/v1") or base, timeout=4.0)
            reachable = True
        except Exception:
            reachable = False
        if reachable:
            line("ok", "LLM endpoint", f"{model} @ {base}")
        else:
            line("warn", "LLM endpoint", f"{model} @ {base}",
                 "endpoint not reachable — is your model server (Ollama/LM Studio/…) running?")

    console.print()
    if ok:
        console.print("[green]Ready.[/]  owlforge run <target>")
    else:
        console.print("[red]Some checks failed[/] — fix the ✗ items above, then re-run `owlforge doctor`.")
    raise typer.Exit(0 if ok else 1)


def _run_hunt(aid, *, target, message, cfg, client, sandbox_client, session_headers,
              identity_set, login_specs, auth_summary, max_turns, scope, emit,
              done_seed=None, checkpoint=None, detected_tech=None, steer_fn=None):
    import asyncio
    summary = ""
    report_path = None
    _examined: set[str] = set()

    try:
        from owlforge.engine.orchestrator import read_blackboard as _rb
        _nsurf = len(_rb(aid))
        _rs = f"recon-summary: mapped {_nsurf} endpoint(s); {auth_summary}"
        if detected_tech:
            _rs += "; tech " + ", ".join(detected_tech)
        emit("status", _rs)
    except Exception:
        pass

    async def _validate_cb():
        # confirm a specialist's findings the moment it finishes, so they surface live
        await validate_findings(assessment_id=aid, sandbox=sandbox_client, emit=emit,
                                session_headers=session_headers, identities=identity_set,
                                skip_ids=_examined)

    from owlforge.engine.orchestrator import run_orchestrated
    summary = asyncio.run(run_orchestrated(
        assessment_id=aid, client=client, sandbox=sandbox_client, emit=emit,
        session_headers=session_headers, scan_mode="deep", target=target,
        max_turns=max(6, max_turns // 2), scope=scope, operator_message=message,
        done_seed=done_seed, checkpoint=checkpoint, validate_cb=_validate_cb,
        detected_tech=detected_tech, steer_fn=steer_fn,
    ))
    # mid-scan re-auth: if a credentialed session expired during the long hunt, re-login
    # (fresh TOTP) so the deterministic passes + validation still run authenticated.
    if login_specs and sandbox_client is not None and session_headers:
        from owlforge.engine.identities import reauth_login, session_alive
        def _reqfn(m, u, headers=None, params=None, body=None):
            try:
                return sandbox_client.http_request(m, u, headers=headers, params=params, body=body)
            except Exception:
                return {}
        if not session_alive(_reqfn, target, session_headers):
            emit("status", "[reauth] session expired mid-scan - re-logging in")
            fresh = reauth_login(login_specs[0], _reqfn,
                                 log=lambda m: emit("status", f"[reauth] {m}"))
            if fresh:
                session_headers.clear()
                session_headers.update(fresh)
                emit("status", "[reauth] session refreshed")
            else:
                emit("log", "[reauth] could not refresh the session automatically")
    try:
        from owlforge.engine.appmodel import build_app_model
        from owlforge.engine.orchestrator import read_blackboard
        from owlforge.engine.scenarios import (
            mass_assignment_scan,
            register_privilege_scan,
            run_business_logic_specialist,
            unauth_action_scan,
            workflow_bypass_scan,
        )
        from owlforge.store.models import SurfaceItem
        with session() as _ms:
            _seeded_urls = [r.url for r in _ms.exec(select(SurfaceItem).where(
                SurfaceItem.assessment_id == aid, SurfaceItem.source == "seeded")).all() if r.url]
        _model = build_app_model(read_blackboard(aid), identity_set, _seeded_urls, detected_tech or [])
        if _model.is_interesting():
            emit("status", "app-model: " + _model.summary().replace(chr(10), " | "))
        from owlforge.engine.stored import stored_scan
        stored_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                    log=lambda m: emit("status", m))
        from owlforge.engine.storedbrowser import browser_stored_scan
        browser_stored_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                            log=lambda m: emit("status", m))
        from owlforge.engine.reflectxss import reflected_xss_scan
        _xss_targets = [{"url": it["url"], "param": _p,
                         "method": (it.get("method") or "GET")}
                        for it in read_blackboard(aid) for _p in (it.get("params") or [])]
        reflected_xss_scan(aid, _xss_targets, sandbox_client, session_headers,
                           log=lambda m: emit("status", m))
        from owlforge.engine.wsprobe import ws_scan
        ws_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                log=lambda m: emit("status", m))
        from owlforge.engine.smuggle import smuggle_scan
        smuggle_scan(aid, target, sandbox_client, log=lambda m: emit("status", m))
        from owlforge.engine.oast import oast_scan
        oast_scan(aid, read_blackboard(aid), sandbox_client, session_headers, cfg.oast,
                  log=lambda m: emit("status", m))
        from owlforge.engine.blindsqli import time_based_sqli_scan
        time_based_sqli_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                             log=lambda m: emit("status", m))
        from owlforge.engine.sqliextract import extract_sqli_values
        extract_sqli_values(aid, sandbox_client, session_headers,
                            log=lambda m: emit("status", m))
        from owlforge.engine.sqlmapconfirm import sqlmap_confirm
        sqlmap_confirm(aid, sandbox_client, session_headers,
                       log=lambda m: emit("status", m))
        from owlforge.engine.graphqlscan import graphql_scan
        graphql_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                     log=lambda m: emit("status", m), target=target)
        from owlforge.engine.accesscontrol import access_control_scan
        access_control_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                            identity_set, log=lambda m: emit("status", m))
        from owlforge.engine.rolematrix import capability_matrix_scan
        capability_matrix_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                               identity_set, log=lambda m: emit("status", m))
        from owlforge.engine.authmatrix import access_matrix_scan
        access_matrix_scan(aid, sandbox_client, session_headers, identity_set,
                           log=lambda m: emit("status", m))
        mass_assignment_scan(aid, _model, sandbox_client, session_headers,
                             log=lambda m: emit("status", m))
        register_privilege_scan(aid, read_blackboard(aid), sandbox_client, target,
                                log=lambda m: emit("status", m))
        unauth_action_scan(aid, _model, sandbox_client, session_headers,
                           log=lambda m: emit("status", m))
        workflow_bypass_scan(aid, _model, sandbox_client, session_headers,
                             log=lambda m: emit("status", m))
        from owlforge.engine.raceprobe import race_scan
        race_scan(aid, _model, sandbox_client, session_headers,
                  log=lambda m: emit("status", m))
        from owlforge.engine.authlogic import jwt_scan
        jwt_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                 log=lambda m: emit("status", m))
        from owlforge.engine.csrf import csrf_scan
        csrf_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                  log=lambda m: emit("status", m))
        from owlforge.engine.corsscan import cors_scan
        cors_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                  log=lambda m: emit("status", m))
        from owlforge.engine.sso import sso_scan
        sso_scan(aid, read_blackboard(aid), sandbox_client, target,
                 session_headers=session_headers, log=lambda m: emit("status", m))
        from owlforge.engine.maliciousdata import malicious_upload_scan, stored_injection_scan
        malicious_upload_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                              log=lambda m: emit("status", m))
        stored_injection_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                              log=lambda m: emit("status", m))
        from owlforge.engine.apiabuse import api_fuzz_scan
        api_fuzz_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                      log=lambda m: emit("status", m))
        from owlforge.engine.apiabuse import method_exposure_scan
        method_exposure_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                             log=lambda m: emit("status", m))
        from owlforge.engine.bizlogic import bizlogic_scan
        bizlogic_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                      log=lambda m: emit("status", m))
        from owlforge.engine.bizlogic import coupon_scan
        coupon_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                    log=lambda m: emit("status", m))
        from owlforge.engine.sessionlogic import session_scan
        session_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                     log=lambda m: emit("status", m))
        from owlforge.engine.sessionfix import session_fixation_scan
        session_fixation_scan(aid, sandbox_client, login_specs, log=lambda m: emit("status", m))
        from owlforge.engine.pwreset import password_reset_scan
        password_reset_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                            target=target, log=lambda m: emit("status", m))
        from owlforge.engine.protopoll import proto_pollution_scan
        proto_pollution_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                             log=lambda m: emit("status", m))
        from owlforge.engine.clientside import postmessage_scan, subdomain_takeover_scan
        postmessage_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                         log=lambda m: emit("status", m))
        subdomain_takeover_scan(aid, read_blackboard(aid), sandbox_client, session_headers,
                                target=target, log=lambda m: emit("status", m))
        if client is not None:
            asyncio.run(run_business_logic_specialist(
                client=client, sandbox=sandbox_client, assessment_id=aid, target=target,
                model=_model, emit=emit, session_headers=session_headers,
                scan_mode="deep", max_turns=max(6, max_turns // 2)))
    except Exception as e:
        emit("log", f"stored pass failed: {type(e).__name__}: {e}")
    emit("status", "final validation sweep")
    asyncio.run(validate_findings(assessment_id=aid, sandbox=sandbox_client, emit=emit,
                                  session_headers=session_headers, identities=identity_set,
                                  skip_ids=_examined))
    # DB is the source of truth now that validation ran incrementally across the hunt
    with session() as _s:
        _vtot = len(_s.exec(select(Finding).where(
            Finding.assessment_id == aid, Finding.status == "validated")).all())
        _cand = len(_s.exec(select(Finding).where(
            Finding.assessment_id == aid, Finding.status == "candidate")).all())
    if _vtot > 0:
        from owlforge.engine.deepen import deepen_findings
        try:
            asyncio.run(deepen_findings(assessment_id=aid, client=client, sandbox=sandbox_client,
                        emit=emit, session_headers=session_headers))
        except Exception as e:
            emit("log", f"deepen phase failed: {e}")
    emit("status", f"validation — {_vtot} validated, {_cand} candidate(s) pending manual review")
    from owlforge.engine.validate import collapse_passive_findings, dedupe_findings
    collapse_passive_findings(aid, emit)
    dedupe_findings(aid, emit)
    try:
        from owlforge.engine.chains import correlate_chains
        correlate_chains(aid, auth_summary=auth_summary, emit=emit)
    except Exception as e:
        emit("log", f"chain correlation failed: {type(e).__name__}: {e}")
    emit("status", "reporting phase")
    _md, report_path = build_and_save_report(aid)
    return summary, report_path


@app.command()
def run(
    target: str = typer.Argument(
        ..., help="Target URL or host (e.g. example.com or https://app.example.com)."),
    message: str = typer.Option(
        "", "--message", "-m",
        help="Optional operator instructions (highest priority): scope, credentials, "
             "in/out-of-scope areas, focus vulns, rate limits, priorities. Free text."),
    scope_in: list[str] = typer.Option(  # noqa: B008
        None, "--scope", help="Extra in-scope host or host/path glob (repeatable; enforced)."),
    scope_out: list[str] = typer.Option(  # noqa: B008
        None, "--out-of-scope", help="Out-of-scope host/path glob (repeatable; wins)."),
    identities: str = typer.Option(
        None, "--identities",
        help="YAML of role-labelled credentials for multi-role / privilege-escalation testing."),
    model: str = typer.Option(
        None, "--model", help="Override the configured model id for this run."),
    network_recon: bool = typer.Option(
        False, "--network-recon",
        help="Also run port/service discovery (nmap) — opt-in (broader authorization)."),
    dashboard_ui: bool = typer.Option(
        True, "--dashboard/--no-dashboard", "-D",
        help="Live full-screen interactive dashboard — the DEFAULT on a terminal. Use "
             "--no-dashboard for the plain scrollable streaming log (and -n for headless CI)."),
    fail_on: str = typer.Option(
        None, "--fail-on",
        help="CI gate: exit non-zero (2) if any VALIDATED finding is at or above this "
             "severity (critical|high|medium|low|info)."),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", "-n",
        help="Headless: plain output, no dashboard, CI-friendly exit codes "
             "(0 clean / 2 findings at/above --fail-on / 1 error)."),
    pull: bool = typer.Option(
        False, "--pull", help="Pull the latest sandbox image before scanning."),
    no_pull: bool = typer.Option(
        False, "--no-pull", help="Skip the sandbox-image freshness check entirely."),
) -> None:
    """Run a deep assessment against TARGET. Thorough by default — recon, interactive SPA
    mapping, pre-probe, specialists, validation, and reporting all run automatically."""
    import hashlib as _hashlib
    import time as _time
    from urllib.parse import urlparse

    _banner()
    cfg = load_config()
    if model:
        cfg = cfg.model_copy(deep=True)
        cfg.llm.model = model
    # normalise the target: accept a bare host, a URL, or a local API description
    target = (target or cfg.testing.default_target or "").strip()
    _spec_items: list = []
    from owlforge.engine.apispec import looks_like_spec_file
    if looks_like_spec_file(target):
        from owlforge.engine.apispec import ingest_spec
        try:
            _base, _spec_items, _kind = ingest_spec(target)
        except Exception as e:
            console.print(f"[red]could not parse API description {target}: {e}[/]")
            raise typer.Exit(1) from e
        if not _base:
            console.print("[red]the spec declares no server/base URL — run against the "
                          "live base URL instead.[/]")
            raise typer.Exit(1)
        console.print(f"[dim]\\[spec] loaded {_kind}: {len(_spec_items)} endpoint(s); "
                      f"base {_base}[/]")
        target = _base
    if target and "://" not in target:
        target = "https://" + target
    if not target:
        console.print("[red]No target. Usage: owlforge run <target>[/]")
        raise typer.Exit(1)
    init_db()

    # deep-by-default: everything thorough, no knobs to dumb it down
    recon_pages = 40
    max_turns = cfg.runner.max_turns   # honor [runner] max_turns (default 40)

    # auto project name: <host>-<shorthash>, filesystem-safe. The assessment id IS this
    # name, so the on-disk folder ~/.owlforge/assessments/<project>/ is self-describing.
    import re as _re0
    host = urlparse(target).netloc or target
    _safehost = _re0.sub(r"[^A-Za-z0-9.-]", "-", host).strip("-") or "target"
    project = f"{_safehost}-{_hashlib.sha1(f'{target}{_time.time()}'.encode()).hexdigest()[:6]}"

    try:
        client = make_client(cfg)
    except LLMError as e:
        console.print(f"[red]{e}[/]")
        console.print(
            f"[dim]Edit {config_path()} and set a model your local server at "
            f"{cfg.llm.base_url} actually serves, then re-run.[/]")
        raise typer.Exit(1) from None

    aid = project
    with session() as s:
        s.add(Assessment(id=aid, project_name=project, target=target,
                         instructions=message, scan_mode="deep", status="executing"))
        s.commit()

    # the sandbox is REQUIRED — a host-only run misses nmap/ffuf/nuclei/katana/Playwright/agentd
    sblog = lambda m: console.print(rf"[dim]\[sandbox] {m}[/]")  # noqa: E731
    if not cfg.sandbox.enabled:
        console.print("[red]Sandbox is disabled in config ([sandbox] enabled=false). "
                      "owlforge needs it for real testing — enable it and re-run.[/]")
        raise typer.Exit(1)
    if not manager.docker_available():
        _eng = manager.container_engine()
        console.print(f"[red]No running container engine — owlforge tried `{_eng}`. "
                      f"{manager.engine_start_hint(_eng)}, then re-run.[/]")
        console.print("[dim]Using Podman? set OWLFORGE_CONTAINER_ENGINE=podman "
                      "(PowerShell: $env:OWLFORGE_CONTAINER_ENGINE=\"podman\") and start "
                      "`podman machine`. See the README \"Using Podman\" section.[/]")
        raise typer.Exit(1)
    if not manager.image_exists(cfg.sandbox.image):
        console.print(rf"[yellow]\[sandbox] image not present locally "
                      f"({cfg.sandbox.image}) — pulling it (first run only)...[/]")
        if not manager.pull_image(cfg.sandbox.image, log=sblog):
            console.print("[red]could not pull the sandbox image. Build it from a source "
                          "checkout with `owlforge sandbox build`, or check your network "
                          "and the image name in ~/.owlforge/config.toml.[/]")
            raise typer.Exit(1)
    _maybe_update_image(cfg.sandbox.image, pull=pull, no_pull=no_pull,
                        interactive=console.is_terminal and not non_interactive)
    try:
        sandbox_session = manager.start(
            cfg.sandbox.image, workspace=str(assessments_dir() / aid), log=sblog)
        sandbox_client = sandbox_session.client
    except Exception as e:
        console.print(f"[red]sandbox start failed:[/] {e}")
        raise typer.Exit(1) from None

    # --- auth: identities file (structured) + login-page harvest; creds may also be in -m ---
    from owlforge.engine.auth import AuthContext

    user_auth = AuthContext(mode="unauth")
    identity_set = None
    login_specs: list[dict] = []
    if identities:
        from owlforge.engine.identities import establish_all, load_identities, primary_identity

        def _estab_reqfn(method, url, headers=None, params=None, body=None):
            try:
                return sandbox_client.http_request(method, url, headers=headers,
                                                   params=params, body=body)
            except Exception as e:
                return {"error": str(e)}

        try:
            _idents = establish_all(load_identities(identities), _estab_reqfn,
                                    log=lambda m: console.print(rf"[dim]\[identities] {m}[/]"))
            _sso_idents = [i for i in _idents if i.needs_sso]
            if _sso_idents and sandbox_session is not None:
                import re as _re
                from urllib.parse import urlsplit as _urlsplit

                from owlforge.engine.authbroker import reuse_or_capture_sso, storage_state_to_headers
                from owlforge.engine.identities import session_alive
                _sso_dir = assessments_dir() / ".sso"
                _sso_dir.mkdir(parents=True, exist_ok=True)
                _host = _re.sub(r"[^A-Za-z0-9.-]", "_", _urlsplit(target).netloc or target)

                def _sso_reqfn(m, u, headers=None, params=None, body=None):
                    try:
                        return sandbox_client.http_request(m, u, headers=headers, params=params,
                                                           body=body)
                    except Exception:
                        return {}

                for ident in _sso_idents:
                    _login_url = ident.auth.get("url") or target
                    # stable per-target path so a valid session is reused across runs
                    ppath = str(_sso_dir / f"{_host}_{ident.label}.json")
                    state = reuse_or_capture_sso(
                        sandbox_client, sandbox_session.novnc_url, _login_url,
                        target=target, persist_path=ppath,
                        is_alive=lambda h: session_alive(_sso_reqfn, target, h),
                        prompt_fn=console.input, log=lambda m: console.print(m))
                    ident.session_headers = storage_state_to_headers(state, target)
                    ident.established = bool(ident.session_headers)
            _prim = primary_identity(_idents)
            _ok = sum(1 for i in _idents if i.session_headers)
            _pending = [i.label for i in _idents if i.needs_sso and not i.session_headers]
            console.print(f"[dim]identities: {len(_idents)} loaded, {_ok} with a session"
                          + (f"; SSO pending: {', '.join(_pending)}" if _pending else "") + "[/]")
            if _prim and _prim.session_headers:
                user_auth = AuthContext(mode="session", headers=_prim.session_headers)
            identity_set = [{"label": i.label, "role": i.role, "headers": i.session_headers}
                            for i in _idents if i.session_headers or i.role == "anonymous"]
            login_specs = [{"url": (i.auth or {}).get("url"), "data": (i.auth or {}).get("data", ""),
                            "success": (i.auth or {}).get("success", ""),
                            "totp_secret": (i.auth or {}).get("totp_secret"),
                            "totp_field": (i.auth or {}).get("totp_field")}
                           for i in _idents if (i.auth or {}).get("type") == "login"
                           and (i.auth or {}).get("url")]
        except Exception as e:
            console.print(f"[yellow]identities load failed: {e}[/]")

    from owlforge.engine.scope import build_scope
    scope = build_scope(target, scope=scope_in, out_of_scope=scope_out, only=None)

    panel = [
        f"project: [bold cyan]{project}[/]   [dim](~/.owlforge/assessments/{project}/)[/]",
        f"target:  {target}",
        f"model:   {cfg.llm.model} @ {cfg.llm.base_url}",
        "sandbox: on",
    ]
    console.print(Panel.fit(chr(10).join(panel), title="assessment started", border_style="cyan"))

    _use_tui = dashboard_ui and console.is_terminal and not non_interactive

    def _checkpoint(keys):
        with session() as _s:
            _a = _s.get(Assessment, aid)
            if _a:
                _a.progress = {**(_a.progress or {}), "done_keys": [list(k) for k in keys]}
                _s.add(_a)
                _s.commit()

    with session() as _s:
        _a0 = _s.get(Assessment, aid)
        _done_seed = (_a0.progress or {}).get("done_keys", []) if _a0 else []

    status = "completed"
    report_path = None
    summary = ""

    # The whole assessment — recon, auth escalation, seeding, then the hunt/validation/report
    # — runs inside this one function so the interactive dashboard (when active) owns EVERY
    # phase, not just the hunt. All logging goes through `emit`, which the dashboard renders
    # live and the plain Emitter prints to the console. (Interactive SSO capture already ran
    # above, before any full-screen UI, because it needs a terminal prompt.)
    def _full(emit, steer=None):
        nonlocal identity_set
        from owlforge.engine.recon import nuclei_scan, persist_new, run_recon, summarize_surface
        surface_text, session_headers, auth_summary = "", {}, ""
        try:
            surface_text, session_headers, auth_summary = run_recon(
                aid, target, sandbox_client, user_auth=user_auth, max_pages=recon_pages,
                network_recon_enabled=network_recon, browser_recon_enabled=True,
                scope=scope, client=client, log=lambda m: emit("status", m))
            emit("status", f"auth: {auth_summary}")
            for _sl in summarize_surface(aid):
                emit("status", _sl)
            try:
                nuclei_scan(aid, target, sandbox_client,
                            log=lambda m: emit("status", f"nuclei: {m}"))
            except Exception as e:
                emit("log", f"nuclei failed: {e}")
        except Exception as e:
            emit("error", f"recon failed: {type(e).__name__}: {e}")

        if _spec_items:
            _added = persist_new(aid, _spec_items, cap=400)
            emit("status", f"spec: seeded {_added} endpoint(s) from the API description")
            try:
                from owlforge.engine.apiabuse import api_auth_scan
                api_auth_scan(aid, _spec_items, sandbox_client,
                              log=lambda m: emit("status", f"api-auth: {m}"))
            except Exception as e:
                emit("log", f"api-auth failed: {e}")

        # stateful seeding: register a throwaway account (+ a 2nd for A-vs-B) and create marker
        # objects (form / JSON / multipart / GraphQL), so access-control runs on owlforge's data.
        try:
            from owlforge.engine.orchestrator import read_blackboard as _rbb
            from owlforge.engine.seed import graphql_seed_objects, register_account, seed_objects
            _inv = _rbb(aid)
            _slog = lambda m: emit("status", f"seed: {m}")  # noqa: E731
            if identity_set is None and session_headers:
                identity_set = [{"label": "session", "role": "user", "headers": session_headers}]
            _reg = register_account(_inv, sandbox_client, target, log=_slog)
            if _reg:
                _reg["label"] = "owlforge-user-a"
                if not session_headers and _reg.get("headers"):
                    session_headers = _reg["headers"]   # no operator creds — operate as this account
                    _slog("no operator session — operating as a self-registered account")
                if identity_set is None:
                    identity_set = []
                identity_set.append(_reg)
                # a second throwaway account enables horizontal (A-vs-B) access-control testing
                _reg2 = register_account(_inv, sandbox_client, target, log=_slog)
                if _reg2 and _reg2.get("headers") and _reg2.get("headers") != _reg.get("headers"):
                    _reg2["label"] = "owlforge-user-b"
                    identity_set.append(_reg2)
                    _slog("provisioned a second throwaway account for A-vs-B authz testing")
            _seeded = seed_objects(_inv, sandbox_client, session_headers, target, log=_slog)
            if _seeded:
                persist_new(aid, _seeded, cap=400)
                emit("status", f"seed: created {len(_seeded)} test object(s) for access-control testing")
            _gseeded = graphql_seed_objects(_inv, sandbox_client, session_headers, target, log=_slog)
            if _gseeded:
                emit("status", f"seed: created {len(_gseeded)} GraphQL object(s)")
                from owlforge.engine.graphqlscan import graphql_idor_scan
                graphql_idor_scan(aid, _gseeded, sandbox_client, session_headers,
                                  identity_set, log=_slog)
        except Exception as e:
            emit("log", f"seed step skipped: {type(e).__name__}: {e}")

        import re as _re
        _tm = _re.search(r"tech=([^;\n]+)", surface_text or "")
        detected_tech = [t.strip() for t in _tm.group(1).split(",")] if _tm else []
        detected_tech = [t for t in detected_tech if t and t != "?"]

        return _run_hunt(
            aid, target=target, message=message, cfg=cfg, client=client,
            sandbox_client=sandbox_client, session_headers=session_headers,
            identity_set=identity_set, login_specs=login_specs,
            auth_summary=auth_summary, max_turns=max_turns, scope=scope, emit=emit,
            done_seed=_done_seed, checkpoint=_checkpoint, detected_tech=detected_tech,
            steer_fn=steer)

    try:
        if _use_tui:
            from owlforge.engine.tui import run_scan_tui
            status, summary, report_path = run_scan_tui(aid, target, cfg.llm.model, _full)
        else:
            emit = Emitter(aid, console=console)
            summary, report_path = _full(emit)
    except KeyboardInterrupt:
        status = "stopped"
        console.print("[yellow]interrupted[/]")
    except Exception as e:
        status = "failed"
        console.print(f"[red]scan error: {type(e).__name__}: {e}[/]")
    finally:
        if sandbox_session:
            manager.stop(sandbox_session, log=sblog)

    with session() as s:
        a = s.get(Assessment, aid)
        if a:
            a.status = status
            s.add(a)
            s.commit()

    with session() as s:
        fcount = len(s.exec(select(Finding).where(Finding.assessment_id == aid)).all())
        vcount = len(s.exec(select(Finding).where(
            Finding.assessment_id == aid, Finding.status == "validated")).all())
    tail = f"\n\nfindings: {vcount} validated / {fcount} total"
    if report_path:
        tail += f"\nreport: {report_path}"
    console.print(
        Panel.fit(
            (summary or "(no summary)") + tail,
            title=f"assessment {status}",
            border_style="green" if status == "completed" else "red",
        )
    )

    # CI exit codes: 1 = error, 2 = a validated finding at/above --fail-on, else 0
    if status == "failed":
        raise typer.Exit(1)
    with session() as s:
        _vsev = [f.severity for f in s.exec(select(Finding).where(
            Finding.assessment_id == aid, Finding.status == "validated")).all()]
    if _meets_fail_threshold(_vsev, fail_on):
        console.print(f"[red]--fail-on {fail_on}: a validated finding meets the threshold "
                      "-> exit 2[/]")
        raise typer.Exit(2)


@app.command()
def resume(assessment_id: str) -> None:
    """Resume an interrupted assessment — skips specialists already completed (checkpointed)."""
    init_db()
    cfg = load_config()
    with session() as s:
        a = s.get(Assessment, assessment_id)
    if not a:
        console.print(f"[red]No such assessment: {assessment_id}[/]")
        raise typer.Exit(1)
    if a.status == "completed":
        console.print(f"[yellow]{assessment_id} already completed — see `owlforge report "
                      f"{assessment_id}`.[/]")
        raise typer.Exit(0)
    aid, target, message = a.id, a.target, a.instructions
    try:
        client = make_client(cfg)
    except LLMError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None
    sblog = lambda m: console.print(rf"[dim]\[sandbox] {m}[/]")  # noqa: E731
    if not cfg.sandbox.enabled or not manager.docker_available() \
            or not manager.image_exists(cfg.sandbox.image):
        console.print("[red]Sandbox/Docker not available. Start Docker and "
                      "`owlforge sandbox build`, then resume.[/]")
        raise typer.Exit(1)
    sandbox_session = manager.start(cfg.sandbox.image, workspace=str(assessments_dir() / aid),
                                    log=sblog)
    sandbox_client = sandbox_session.client
    from owlforge.engine.auth import AuthContext
    from owlforge.engine.recon import run_recon
    from owlforge.engine.scope import build_scope
    scope = build_scope(target)
    console.print(f"[cyan]resuming {aid} → {target}[/]")
    session_headers, auth_summary = {}, ""
    try:
        _st, session_headers, auth_summary = run_recon(
            aid, target, sandbox_client, user_auth=AuthContext(mode="unauth"),
            max_pages=40, browser_recon_enabled=True, scope=scope, client=client,
            log=lambda m: console.print(rf"[dim]\[recon] {m}[/]"))
    except Exception as e:
        console.print(f"[yellow]recon failed: {e}[/]")
    emit = Emitter(aid, console=console)

    def _checkpoint(keys):
        with session() as _s:
            _a = _s.get(Assessment, aid)
            if _a:
                _a.progress = {**(_a.progress or {}), "done_keys": [list(k) for k in keys]}
                _s.add(_a)
                _s.commit()

    with session() as _s:
        _a0 = _s.get(Assessment, aid)
        _done_seed = (_a0.progress or {}).get("done_keys", []) if _a0 else []
    console.print(f"[dim]resuming past {len(_done_seed)} completed specialist target(s)[/]")

    status, summary, report_path = "completed", "", None
    try:
        summary, report_path = _run_hunt(
            aid, target=target, message=message, cfg=cfg, client=client,
            sandbox_client=sandbox_client, session_headers=session_headers,
            identity_set=None, login_specs=[], auth_summary=auth_summary,
            max_turns=24, scope=scope, emit=emit, done_seed=_done_seed, checkpoint=_checkpoint)
    except KeyboardInterrupt:
        status = "stopped"
        console.print("[yellow]interrupted[/]")
    except Exception as e:
        status = "failed"
        emit("error", f"{type(e).__name__}: {e}")
    finally:
        manager.stop(sandbox_session, log=sblog)
    with session() as s:
        a = s.get(Assessment, aid)
        if a:
            a.status = status
            s.add(a)
            s.commit()
    console.print(Panel.fit(
        (summary or "(resumed)") + (f"\nreport: {report_path}" if report_path else ""),
        title=f"assessment {status}", border_style="green" if status == "completed" else "red"))


@assessments_app.command("list")
def assessments_list() -> None:
    """List recorded assessments."""
    init_db()
    with session() as s:
        rows = s.exec(select(Assessment).order_by(Assessment.created_at.desc())).all()
    if not rows:
        console.print('[dim]No assessments yet. Start one with `owlforge run -m "..."`.[/]')
        return
    table = Table(title="assessments")
    for col in ("id", "project", "target", "mode", "status", "created"):
        table.add_column(col)
    for a in rows:
        table.add_row(a.id, a.project_name, a.target, a.scan_mode, a.status,
                      a.created_at.isoformat(timespec="seconds"))
    console.print(table)


@assessments_app.command("show")
def assessments_show(assessment_id: str) -> None:
    """Show one assessment."""
    init_db()
    with session() as s:
        a = s.get(Assessment, assessment_id)
    if not a:
        console.print(f"[red]No assessment {assessment_id}[/]")
        raise typer.Exit(1)
    console.print(a.model_dump())


@app.command()
def findings(assessment_id: str) -> None:
    """List findings for an assessment."""
    init_db()
    with session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
    if not rows:
        console.print("[dim]No findings (finding-filing lands in Phase 3).[/]")
        return
    table = Table(title=f"findings — {assessment_id}")
    for col in ("id", "severity", "status", "title"):
        table.add_column(col)
    for f in rows:
        table.add_row(f.id, f.severity, f.status, f.title)
    console.print(table)


@app.command()
def report(
    assessment_id: str,
    rebuild: bool = typer.Option(False, "--rebuild", help="Rebuild from current findings."),
    fmt: str = typer.Option("md", "--format", "-f",
                            help="Output format: md | html | sarif | all."),
) -> None:
    """Print or write the assessment report (markdown / HTML / SARIF)."""
    init_db()
    fmt = (fmt or "md").lower()
    build = rebuild or fmt != "md"
    if build:
        md, _ = build_and_save_report(assessment_id)  # emits md + html + sarif
    else:
        with session() as s:
            rep = s.get(Report, assessment_id)
        if not rep or not rep.body_markdown:
            console.print("[yellow]No report yet. Run the assessment, or use --rebuild.[/]")
            raise typer.Exit(1)
        md = rep.body_markdown
    if fmt in ("md", "all"):
        console.print(md)
    from owlforge.config import assessments_dir
    d = assessments_dir() / assessment_id
    names = {"html": ["report.html"], "sarif": ["report.sarif.json"],
             "all": ["report.md", "report.html", "report.sarif.json"]}.get(fmt, [])
    for name in names:
        fp = d / name
        if fp.exists():
            console.print(f"[dim]written: {fp}[/]")


@app.command()
def diff(
    assessment_id: str,
    against: str = typer.Option(None, "--against", help="Compare to this assessment id "
                                "(default: the previous run of the same project/target)."),
) -> None:
    """Show what changed vs a previous scan: new / fixed / still-present findings."""
    init_db()
    from sqlmodel import select

    from owlforge.report.diff import diff_findings, previous_assessment_id
    with session() as s:
        cur_asmt = s.get(Assessment, assessment_id)
        if not cur_asmt:
            console.print(f"[red]No such assessment: {assessment_id}[/]")
            raise typer.Exit(1)
        prev_id = against or previous_assessment_id(cur_asmt)
        if not prev_id:
            console.print("[yellow]No previous assessment of this project/target to diff against.[/]")
            raise typer.Exit(0)
        current = list(s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all())
        previous = list(s.exec(select(Finding).where(Finding.assessment_id == prev_id)).all())
    d = diff_findings(current, previous)
    console.print(f"[bold]diff[/] {assessment_id} vs {prev_id}")
    for label, color, items in (("NEW", "red", d["new"]),
                                ("FIXED", "green", d["fixed"]),
                                ("PERSISTING", "yellow", d["persisting"])):
        console.print(f"[{color}]{label} ({len(items)})[/]")
        for title, ep in items:
            console.print(f"   • {title}" + (f"  [dim]{ep}[/]" if ep else ""))


@sandbox_app.command("build")
def sandbox_build() -> None:
    """Build the owlforge-sandbox image from ./sandbox."""
    from pathlib import Path

    cfg = load_config()
    ctx_dir = Path(__file__).resolve().parents[1] / "sandbox"
    if not (ctx_dir / "Dockerfile").exists():
        console.print(f"[red]No Dockerfile at {ctx_dir}[/] (run from a source checkout).")
        raise typer.Exit(1)
    if not manager.docker_available():
        console.print("[red]Docker is not available.[/]")
        raise typer.Exit(1)
    ok = manager.build_image(cfg.sandbox.image, ctx_dir, log=lambda m: console.print(f"[dim]{m}[/]"))
    console.print(f"[green]built {cfg.sandbox.image}[/]" if ok else "[red]build failed[/]")
    raise typer.Exit(0 if ok else 1)


@sandbox_app.command("pull")
def sandbox_pull() -> None:
    """Pull the latest sandbox image from the registry."""
    cfg = load_config()
    if not manager.docker_available():
        console.print("[red]Docker is not running.[/]")
        raise typer.Exit(1)
    ok = manager.pull_image(cfg.sandbox.image, log=lambda m: console.print(f"[dim]{m}[/]"))
    console.print("[green]image pulled[/]" if ok else "[red]pull failed[/]")
    raise typer.Exit(0 if ok else 1)


@sandbox_app.command("update")
def sandbox_update() -> None:
    """Pull the sandbox image only if the registry has a newer one."""
    cfg = load_config()
    avail = manager.update_available(cfg.sandbox.image)
    if avail is None:
        console.print("[dim]can't determine freshness (local build or registry "
                      "unreachable); nothing to do.[/]")
    elif not avail:
        console.print("[green]sandbox image is already up to date[/]")
    else:
        manager.pull_image(cfg.sandbox.image, log=lambda m: console.print(f"[dim]{m}[/]"))
        console.print("[green]updated[/]")


@sandbox_app.command("status")
def sandbox_status() -> None:
    """Show docker availability + whether the sandbox image is built."""
    cfg = load_config()
    docker = manager.docker_available()
    built = docker and manager.image_exists(cfg.sandbox.image)
    console.print({
        "docker_available": docker,
        "image": cfg.sandbox.image,
        "image_built": built,
        "agentd_container_port": manager.AGENTD_CONTAINER_PORT,
    })


@sandbox_app.command("info")
def sandbox_info() -> None:
    """Show the configured sandbox image + daemon port."""
    cfg = load_config()
    console.print({"image": cfg.sandbox.image, "agentd_port": cfg.sandbox.agentd_port, "enabled": cfg.sandbox.enabled})


@app.command()
def bench(
    models: str = typer.Option(..., "--models", help="Comma-separated model ids to benchmark."),
    message: str = typer.Option(..., "--message", "-m", help="Mission instructions (same for all)."),
    target: str = typer.Option(None, "--target", "-t", help="Target (defaults to testing target)."),
    mode: str = typer.Option("standard", "--mode"),
    max_turns: int = typer.Option(16, "--max-turns"),
    oracle: str = typer.Option(None, "--oracle", help="Substring; a VALIDATED finding containing it = recall hit."),
    offload: bool = typer.Option(True, "--offload/--no-offload", help="Offload other Ollama models between runs."),
) -> None:
    """Run one mission across several models and emit a scored compatibility matrix."""
    import json
    from datetime import datetime

    from owlforge.bench.runner import run_bench
    from owlforge.config import owlforge_home

    model_list = [m.strip() for m in models.split(",") if m.strip()]
    if not model_list:
        console.print("[red]No models given.[/]")
        raise typer.Exit(1)

    results, matrix = run_bench(
        model_list, mission=message, target=target, scan_mode=mode, max_turns=max_turns,
        oracle=oracle, offload=offload, log=lambda m: console.print(f"[dim]{m}[/]"),
    )
    console.print()
    console.print(matrix)

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    outdir = owlforge_home() / "bench" / ts
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "matrix.md").write_text(matrix + "\n", encoding="utf-8")
    (outdir / "results.json").write_text(
        json.dumps([r.__dict__ for r in results], indent=2), encoding="utf-8"
    )
    console.print(f"[green]bench written:[/] {outdir}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
