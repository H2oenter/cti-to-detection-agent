"""cti-agent: the command-line entry point.

Every command is read-only except `publish --apply`, which is the only path that
sends data anywhere (design rule 5).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from cti_agent import __version__

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Turn public threat reports into evidence-checked STIX, coverage gaps and draft KQL.",
)
console = Console()


def _not_yet(milestone: str) -> None:
    console.print(f"[yellow]Not implemented yet ({milestone}).[/yellow]")
    raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the version."""
    console.print(__version__)


@app.command()
def ingest(
    path: Annotated[Path, typer.Argument(help="Local report file: PDF, HTML or text.")],
    tlp: Annotated[str, typer.Option(help="TLP of the source.")] = "CLEAR",
) -> None:
    """Stages 1-3: extract, validate and store a report."""
    _not_yet("M1")


@app.command()
def fetch(
    since: Annotated[str, typer.Option(help="Look-back window, e.g. 24h.")] = "24h",
) -> None:
    """Pull fresh vulnerability advisories from the allowlisted feeds (no LLM)."""
    _not_yet("M2")


@app.command()
def analyse(run_id: str) -> None:
    """Stages 4-5: ATT&CK coverage, KQL drafts and reviewer scores."""
    _not_yet("M2")


@app.command()
def review(run_id: str) -> None:
    """Stage 6: approve, reject or edit each draft."""
    _not_yet("M3")


@app.command()
def publish(
    run_id: str,
    target: Annotated[str, typer.Option(help="sentinel, misp or opencti.")] = "sentinel",
    apply: Annotated[
        bool, typer.Option("--apply", help="Actually send. Default is a dry run.")
    ] = False,
) -> None:
    """Build upload payloads for approved items. Dry run unless --apply."""
    _not_yet("M3")


@app.command(name="eval")
def eval_() -> None:
    """Score the pipeline against the gold set and the injection tests."""
    _not_yet("M4")


@app.command()
def trace(run_id: str) -> None:
    """Pretty-print a run's trace."""
    _not_yet("M1")
