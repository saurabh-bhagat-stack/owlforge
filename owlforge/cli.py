"""owlforge command-line interface."""

from __future__ import annotations

import secrets

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlmodel import select

from owlforge import __version__
from owlforge.config import config_path, load_config, owlforge_home, write_default_config
from owlforge.engine.agent import run_single_agent
from owlforge.engine.events import Emitter
from owlforge.llm.client import LLMError, make_client
from owlforge.store.db import init_db, session
from owlforge.store.models import Assessment, Finding
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
) -> None:
    """Start an assessment and run the Phase 1 single-agent loop against a local model."""
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

    console.print(
        Panel.fit(
            f"id:      [bold cyan]{aid}[/]\n"
            f"project: {project}\n"
            f"target:  {target}\n"
            f"model:   {cfg.llm.model} @ {cfg.llm.base_url}\n"
            f"context: {client.context_window} ({client.context_source})\n"
            f"mode:    {mode}",
            title="assessment started",
            border_style="cyan",
        )
    )

    emit = Emitter(aid, console=console)
    registry = build_registry()
    status = "completed"
    summary = ""
    try:
        summary = asyncio.run(
            run_single_agent(
                client=client, registry=registry, emit=emit, assessment_id=aid,
                target=target, instructions=message, scan_mode=mode, max_turns=max_turns,
            )
        )
    except KeyboardInterrupt:
        status = "stopped"
        console.print("[yellow]interrupted[/]")
    except Exception as e:
        status = "failed"
        emit("error", f"{type(e).__name__}: {e}")

    with session() as s:
        a = s.get(Assessment, aid)
        if a:
            a.status = status
            s.add(a)
            s.commit()

    console.print(
        Panel.fit(
            summary or "(no summary)",
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
def report(assessment_id: str) -> None:
    """Render an assessment report. (Phase 3.)"""
    console.print("[yellow]Reporting lands in Phase 3.[/]")


@sandbox_app.command("build")
def sandbox_build(run_it: bool = typer.Option(False, "--run", help="Actually run the build.")) -> None:
    """Build the owlforge-sandbox image (Phase 2 image; Phase 0 prints the command)."""
    cfg = load_config()
    cmd = f"docker build -t {cfg.sandbox.image} ./sandbox"
    console.print(f"[bold]build command:[/] {cmd}")
    if not run_it:
        console.print("[dim]Dry run. Re-run with --run once the sandbox image is fleshed out (Phase 2).[/]")
        return
    import subprocess

    raise SystemExit(subprocess.call(cmd, shell=True))


@sandbox_app.command("info")
def sandbox_info() -> None:
    """Show the configured sandbox image + daemon port."""
    cfg = load_config()
    console.print({"image": cfg.sandbox.image, "agentd_port": cfg.sandbox.agentd_port, "enabled": cfg.sandbox.enabled})


def main() -> None:
    app()


if __name__ == "__main__":
    main()
