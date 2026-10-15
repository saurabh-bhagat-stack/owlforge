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
from owlforge.engine.agent import run_single_agent
from owlforge.engine.events import Emitter
from owlforge.engine.validate import validate_findings
from owlforge.llm.client import LLMError, make_client
from owlforge.report.builder import build_and_save_report
from owlforge.sandbox import manager
from owlforge.store.db import init_db, session
from owlforge.store.models import Assessment, Finding, Report
from owlforge.tools.builtin import build_registry

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
def run(
    target: str = typer.Option(None, "--target", "-t", help="Target URL/host (defaults to testing target)."),
    project: str = typer.Option("default", "--project", "-p", help="Project name."),
    mode: str = typer.Option("standard", "--mode", help="quick | standard | deep"),
    message: str = typer.Option(..., "--message", "-m", help="Plain-language assessment instructions."),
    max_turns: int = typer.Option(20, "--max-turns", help="Max agent turns."),
    model: str = typer.Option(None, "--model", help="Override the configured model id (e.g. saluki-27b:latest)."),
    no_sandbox: bool = typer.Option(False, "--no-sandbox", help="Skip the sandbox even if configured."),
    auth_cookie: str = typer.Option(None, "--auth-cookie", help="Cookie for authenticated recon, e.g. 'session=abc'."),
    auth_header: str = typer.Option(None, "--auth-header", help="Extra header 'Name: Value'."),
    login_url: str = typer.Option(None, "--login-url", help="Form-login URL (authenticated mode)."),
    login_data: str = typer.Option(None, "--login-data", help="urlencoded login fields, e.g. 'username=a&password=b'."),
    login_success: str = typer.Option(None, "--login-success", help="Substring indicating a successful login."),
    recon: bool = typer.Option(True, "--recon/--no-recon", help="Deterministic recon before testing."),
    recon_pages: int = typer.Option(25, "--recon-pages", help="Max pages to crawl during recon."),
    network_recon: bool = typer.Option(False, "--network-recon", help="Also run port/service discovery (nmap)."),
    orchestrate: bool = typer.Option(True, "--orchestrate/--single", help="Multi-agent default (--single = one agent)"),
) -> None:
    """Start an assessment and run the single-agent loop, with the sandbox if available."""
    import asyncio

    cfg = load_config()
    if model:
        cfg = cfg.model_copy(deep=True)
        cfg.llm.model = model
    target = target or cfg.testing.default_target
    init_db()

    try:
        client = make_client(cfg)
    except LLMError as e:
        console.print(f"[red]{e}[/]")
        console.print(
            f"[dim]Edit {config_path()} and set a model your local server at "
            f"{cfg.llm.base_url} actually serves, then re-run.[/]"
        )
        raise typer.Exit(1) from None

    aid = _new_id("asmt")
    with session() as s:
        s.add(
            Assessment(
                id=aid, project_name=project, target=target,
                instructions=message, scan_mode=mode, status="executing",
            )
        )
        s.commit()

    sblog = lambda m: console.print(rf"[dim]\[sandbox] {m}[/]")  # noqa: E731
    sandbox_session = None
    sandbox_client = None
    if cfg.sandbox.enabled and not no_sandbox:
        if not manager.docker_available():
            console.print("[yellow]Docker not available — running without the sandbox (exec_command disabled).[/]")
        elif not manager.image_exists(cfg.sandbox.image):
            console.print(
                f"[yellow]Sandbox image not built ({cfg.sandbox.image}). Run "
                f"'owlforge sandbox build'. Running without exec_command for now.[/]"
            )
        else:
            try:
                sandbox_session = manager.start(
                    cfg.sandbox.image, workspace=str(assessments_dir() / aid), log=sblog
                )
                sandbox_client = sandbox_session.client
            except Exception as e:
                console.print(f"[red]sandbox start failed:[/] {e}")
                console.print("[yellow]running without exec_command[/]")

    # --- authentication (unauth | session | login) ---
    from urllib.parse import parse_qsl

    from owlforge.engine.auth import AuthContext, establish_session

    _extra: dict[str, str] = {}
    if auth_header and ":" in auth_header:
        _hk, _hv = auth_header.split(":", 1)
        _extra[_hk.strip()] = _hv.strip()
    if auth_cookie:
        _extra["Cookie"] = auth_cookie
    session_headers: dict[str, str] = {}
    if login_url:
        _auth = AuthContext(mode="login", headers=_extra, login_url=login_url,
                            login_params=dict(parse_qsl(login_data or "")), login_success=login_success)
    elif _extra:
        _auth = AuthContext(mode="session", headers=_extra)
    else:
        _auth = AuthContext(mode="unauth")

    if _auth.mode != "unauth":
        def _reqfn(method, url, headers=None, params=None, body=None):
            import httpx
            try:
                r = httpx.request(method, url, headers=headers, params=params, content=body,
                                  follow_redirects=False, timeout=20.0)
                return {"status": r.status_code, "headers": dict(r.headers), "body": r.text}
            except Exception as e:
                return {"error": str(e)}
        session_headers = establish_session(_auth, _reqfn, log=lambda m: console.print(f"[dim]\[auth] {m}[/]"))
        console.print(f"[dim]auth mode={_auth.mode}, session {'established' if session_headers else 'empty'}[/]")

    panel = [
        f"id:      [bold cyan]{aid}[/]",
        f"project: {project}",
        f"target:  {target}",
        f"model:   {cfg.llm.model} @ {cfg.llm.base_url}",
        f"context: {client.context_window} ({client.context_source})",
        f"sandbox: {'on' if sandbox_client else 'off'}",
        f"auth:    {_auth.mode}",
        f"mode:    {mode}",
    ]
    console.print(Panel.fit(chr(10).join(panel), title="assessment started", border_style="cyan"))

    surface_text = ""
    if recon:
        from owlforge.engine.recon import recon_phase
        try:
            surface_text = recon_phase(aid, target, session_headers, sandbox_client,
                                       max_pages=recon_pages, network_recon_enabled=network_recon,
                                       log=lambda m: console.print(f"[dim]\[recon] {m}[/]"))
            if surface_text:
                console.print(f"[dim]\[recon] surface inventory:\n{surface_text[:700]}[/]")
        except Exception as e:
            console.print(f"[yellow]recon failed: {e}[/]")

    emit = Emitter(aid, console=console)
    registry = build_registry(with_sandbox=sandbox_client is not None)
    status = "completed"
    summary = ""
    report_path = None
    try:
        if orchestrate:
            from owlforge.engine.orchestrator import run_orchestrated
            summary = asyncio.run(run_orchestrated(
                assessment_id=aid, client=client, sandbox=sandbox_client, emit=emit,
                session_headers=session_headers, scan_mode=mode, target=target,
                max_turns=max(6, max_turns // 2),
            ))
        else:
            summary = asyncio.run(
                run_single_agent(
                    client=client, registry=registry, emit=emit, assessment_id=aid,
                    target=target, instructions=message, scan_mode=mode, max_turns=max_turns,
                    sandbox=sandbox_client, session_headers=session_headers,
                    surface=surface_text or None,
                )
            )
        emit("status", "validation phase")
        vcounts = asyncio.run(validate_findings(assessment_id=aid, sandbox=sandbox_client, emit=emit))
        emit("status", f"validation — {vcounts['validated']} validated, "
                       f"{vcounts['rejected']} rejected, {vcounts['manual']} manual")
        emit("status", "reporting phase")
        _md, report_path = build_and_save_report(aid)
    except KeyboardInterrupt:
        status = "stopped"
        console.print("[yellow]interrupted[/]")
    except Exception as e:
        status = "failed"
        emit("error", f"{type(e).__name__}: {e}")
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
) -> None:
    """Print the assessment report (markdown)."""
    init_db()
    if rebuild:
        md, path = build_and_save_report(assessment_id)
        console.print(md)
        if path:
            console.print(f"[dim]written: {path}[/]")
        return
    with session() as s:
        rep = s.get(Report, assessment_id)
    if not rep or not rep.body_markdown:
        console.print("[yellow]No report yet. Run the assessment, or use --rebuild.[/]")
        raise typer.Exit(1)
    console.print(rep.body_markdown)


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
