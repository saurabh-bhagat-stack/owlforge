"""owlforge command-line interface (Phase 0 skeleton).

Commands exist and the store works end-to-end; the agentic engine, sandbox, and
report rendering are stubbed until later phases.
"""

from __future__ import annotations

import secrets

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlmodel import select

from owlforge import __version__
from owlforge.config import load_config, owlforge_home, write_default_config
from owlforge.store.db import init_db, session
from owlforge.store.models import Assessment, Finding

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
) -> None:
    """Start an assessment. (Phase 0: records it; the engine lands in Phase 1.)"""
    cfg = load_config()
    target = target or cfg.testing.default_target
    init_db()
    eid = _new_id("asmt")
    with session() as s:
        s.add(
            Assessment(
                id=eid,
                project_name=project,
                target=target,
                instructions=message,
                scan_mode=mode,
                status="created",
            )
        )
        s.commit()
    console.print(
        Panel.fit(
            f"id:      [bold cyan]{eid}[/]\n"
            f"project: {project}\n"
            f"target:  {target}\n"
            f"mode:    {mode}\n"
            f"status:  created",
            title="assessment created",
            border_style="cyan",
        )
    )
    console.print(
        "[yellow]Engine not implemented yet (Phase 1).[/] The assessment is recorded; "
        "nothing is executed against the target."
    )


@assessments_app.command("list")
def assessments_list() -> None:
    """List recorded assessments."""
    init_db()
    with session() as s:
        rows = s.exec(select(Assessment).order_by(Assessment.created_at.desc())).all()
    if not rows:
        console.print("[dim]No assessments yet. Start one with `owlforge run -m \"...\"`.[/]")
        return
    table = Table(title="assessments")
    for col in ("id", "project", "target", "mode", "status", "created"):
        table.add_column(col)
    for e in rows:
        table.add_row(e.id, e.project_name, e.target, e.scan_mode, e.status, e.created_at.isoformat(timespec="seconds"))
    console.print(table)


@assessments_app.command("show")
def assessments_show(assessment_id: str) -> None:
    """Show one assessment."""
    init_db()
    with session() as s:
        e = s.get(Assessment, assessment_id)
    if not e:
        console.print(f"[red]No assessment {assessment_id}[/]")
        raise typer.Exit(1)
    console.print(e.model_dump())


@app.command()
def findings(assessment_id: str) -> None:
    """List findings for an assessment."""
    init_db()
    with session() as s:
        rows = s.exec(select(Finding).where(Finding.assessment_id == assessment_id)).all()
    if not rows:
        console.print("[dim]No findings (nothing runs until Phase 3).[/]")
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
