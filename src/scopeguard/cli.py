"""Command-line interface.

Exit codes:
  0  the command completed
  1  an unexpected failure aborted the command
  2  the configuration or invocation is invalid
  4  --fail-on confirmed, and at least one confirmed finding was recorded
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from scopeguard import __version__
from scopeguard.errors import ConfigError, ScopeGuardError
from scopeguard.reporting import write_reports
from scopeguard.reporting.json_report import load_assessment_result
from scopeguard.reporting.markdown_report import render_markdown
from scopeguard.runner import run_assessment
from scopeguard.scope import load_assessment

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    invoke_without_command=True,
    help="Scope-aware reconnaissance and validation for authorized assessments.",
)
config_app = typer.Typer(
    add_completion=False, no_args_is_help=True, help="Inspect an assessment file."
)
app.add_typer(config_app, name="config")

ConfigOption = Annotated[
    Path,
    typer.Option(
        "--config", exists=True, dir_okay=False, readable=True, help="Assessment YAML file."
    ),
]


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version, is_eager=True, help="Print the version and exit."
        ),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Print each observation and finding.")
    ] = False,
) -> None:
    """Scope-aware reconnaissance and validation for authorized assessments."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(2)


@config_app.command("validate")
def validate_config(config: ConfigOption) -> None:
    """Check an assessment file and print the authorized surface. Makes no requests."""
    loaded = _load(config)
    schemes = sorted({entry.scheme for entry in loaded.hosts})
    typer.echo("valid")
    typer.echo(f"name: {loaded.name}")
    typer.echo(f"hosts: {len(loaded.hosts)}")
    typer.echo(f"schemes: {', '.join(schemes)}")
    typer.echo(f"recon: {', '.join(loaded.recon) or '(none)'}")
    typer.echo(f"checks: {', '.join(loaded.checks) or '(none)'}")
    typer.echo(f"allow_public: {str(loaded.allow_public).lower()}")
    typer.echo(f"allow_private: {str(loaded.allow_private).lower()}")
    typer.echo(f"allow_loopback: {str(loaded.allow_loopback).lower()}")


@app.command("scan")
def scan(
    ctx: typer.Context,
    config: ConfigOption,
    output: Annotated[
        Path, typer.Option("--output", help="Directory for assessment.json and assessment.md.")
    ],
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on", help="Exit 4 when this result is present. Only 'confirmed' is accepted."
        ),
    ] = None,
) -> None:
    """Run the enabled modules and write a report. Does not scan unlisted targets."""
    if fail_on not in {None, "confirmed"}:
        _exit(f"error: --fail-on accepts only 'confirmed', not {fail_on!r}", 2)
    if output.exists() and not output.is_dir():
        _exit(f"error: output path is a file: {output}", 2)
    loaded = _load(config)
    try:
        assessment = run_assessment(loaded)
    except ScopeGuardError as exc:
        _exit(f"error: {exc}", 1)
    written = write_reports(assessment, output, list(loaded.output.formats))
    confirmed = sum(1 for item in assessment.findings if item.status.value == "confirmed")
    typer.echo(f"assessment: {assessment.name}")
    typer.echo(f"observations: {len(assessment.observations)}")
    typer.echo(f"confirmed: {confirmed}")
    typer.echo(f"findings: {len(assessment.findings)}")
    for path in written:
        typer.echo(f"wrote: {path}")
    if ctx.obj.get("verbose"):
        for item in assessment.observations:
            typer.echo(f"observe {item.module} {item.status} {item.target}", err=True)
        for item in assessment.findings:
            typer.echo(f"finding {item.status.value} {item.check} {item.endpoint}", err=True)
    if fail_on == "confirmed" and confirmed:
        raise typer.Exit(4)


@app.command("report")
def report(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input",
            exists=True,
            dir_okay=False,
            readable=True,
            help="assessment.json from a scan.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write Markdown here. Prints to stdout when omitted."),
    ] = None,
) -> None:
    """Render a Markdown report from an existing assessment JSON file."""
    try:
        assessment = load_assessment_result(input_path)
    except ConfigError as exc:
        _exit(f"error: {exc}", 2)
    rendered = render_markdown(assessment)
    if output is None:
        typer.echo(rendered, nl=False)
        return
    if output.exists() and output.is_dir():
        _exit(f"error: output path is a directory: {output}", 2)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    typer.echo(f"wrote: {output}")


def _load(path: Path):
    try:
        return load_assessment(path)
    except ConfigError as exc:
        _exit(f"error: {exc}", 2)


def _exit(message: str, code: int) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(code)
