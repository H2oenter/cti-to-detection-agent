"""cti-agent: the command-line entry point.

Every command is read-only except `publish --apply`, which is the only path that
sends data anywhere (design rule 5).
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from cti_agent import __version__
from cti_agent.config import Settings
from cti_agent.inputs import InputError
from cti_agent.llm.client import (
    AnthropicClient,
    FatalLLMError,
    FixtureMissing,
    LLMClient,
    RecordingClient,
    ReplayClient,
)
from cti_agent.pipeline import IngestBlocked, IngestResult, run_ingest
from cti_agent.trace import read_trace


class TLPLevel(StrEnum):
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    AMBER_STRICT = "AMBER+STRICT"
    RED = "RED"


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
    tlp: Annotated[TLPLevel, typer.Option(case_sensitive=False, help="TLP of the source.")] = (
        TLPLevel.CLEAR
    ),
    replay: Annotated[
        Path | None, typer.Option(help="Replay recorded model responses from this folder.")
    ] = None,
    record: Annotated[
        Path | None, typer.Option(help="Save model responses to this folder as test fixtures.")
    ] = None,
) -> None:
    """Stages 1-3: extract, validate and store a report."""
    settings = Settings()
    client: LLMClient
    if replay:
        client = ReplayClient(replay)
    else:
        key = settings.anthropic_api_key
        client = AnthropicClient(
            api_key=key.get_secret_value() if key else None,
            workspace_id=settings.anthropic_workspace_id,
        )
    if record:
        client = RecordingClient(client, record)

    try:
        result = run_ingest(path, tlp.value, settings, client)
    except IngestBlocked as exc:
        console.print(f"[red]Blocked:[/red] {exc}")
        raise typer.Exit(code=2) from None
    except (InputError, FileNotFoundError, FixtureMissing) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    except FatalLLMError as exc:
        console.print(f"[red]Model call failed, run stopped:[/red] {exc}")
        raise typer.Exit(code=3) from None
    _print_ingest(result)


def _label_value(item_type: str, item: dict) -> tuple[str, str]:
    label = f"{item_type}:{item['kind']}" if "kind" in item else item_type
    for key in ("value", "attack_id", "name", "cve_id"):
        if item.get(key):
            return label, str(item[key])
    return label, ""


def _print_ingest(result: IngestResult) -> None:
    s = result.summary
    colour = {"complete": "green", "partial": "yellow", "failed": "red"}[s.status]
    stop = f" (stopped: {s.stop_reason})" if s.stop_reason else ""
    console.print(f"\n[bold]Run[/bold] {s.run_id}  [{colour}]{s.status}{stop}[/{colour}]")
    console.print(f"Source: {s.source_file}   chunks: {s.chunks_done}/{s.chunks_total}")

    accepted = Table(title="Accepted (quote verified in source)", title_justify="left")
    accepted.add_column("Type")
    accepted.add_column("Value")
    accepted.add_column("Evidence")
    accepted.add_column("Page", justify="right")
    for a in result.validation.accepted:
        label, value = _label_value(a.item_type, a.item.model_dump())
        warn = " [yellow](!)[/yellow]" if a.warnings else ""
        accepted.add_row(label, f"{value}{warn}", a.evidence_kind, str(a.page or ""))
    console.print(accepted)

    if result.validation.rejected:
        rejected = Table(title="Rejected, and why", title_justify="left")
        rejected.add_column("Type")
        rejected.add_column("Value", overflow="fold")
        rejected.add_column("Reason", style="red")
        rejected.add_column("Detail", overflow="fold")
        for r in result.validation.rejected:
            label, value = _label_value(r.item_type, r.item)
            rejected.add_row(label, value, r.reason, r.detail)
        console.print(rejected)

    console.print(
        f"Tokens: {s.input_tokens:,} in / {s.output_tokens:,} out   est. cost ${s.est_cost_usd:.4f}"
    )
    console.print(f"Outputs: {result.out_dir}")


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
    path = Settings().out_dir / run_id / "trace.jsonl"
    if not path.exists():
        console.print(f"[red]No trace at {path}[/red]")
        raise typer.Exit(code=2)
    rows = read_trace(path)
    table = Table(title=f"Trace {run_id}", title_justify="left")
    for col in ("Stage", "Step", "Model", "In", "Out", "ms", "Cost $", "Outcome", "Detail"):
        justify = "right" if col in ("In", "Out", "ms", "Cost $") else "left"
        table.add_column(col, justify=justify, overflow="fold")
    for r in rows:
        style = None if r["outcome"] == "ok" else "yellow"
        table.add_row(
            r["stage"],
            r["step"],
            r["model"] or "",
            f"{r['input_tokens']:,}",
            f"{r['output_tokens']:,}",
            str(r["latency_ms"]),
            f"{r['est_cost_usd']:.4f}",
            r["outcome"],
            r["detail"] or "",
            style=style,
        )
    total_in = sum(r["input_tokens"] for r in rows)
    total_out = sum(r["output_tokens"] for r in rows)
    total_cost = sum(r["est_cost_usd"] for r in rows)
    table.add_section()
    table.add_row(
        "total", "", "", f"{total_in:,}", f"{total_out:,}", "", f"{total_cost:.4f}", "", "",
        style="bold",
    )  # fmt: skip
    console.print(table)
    budget = rows[-1]["budget"] if rows else 0
    console.print(f"Budget used: {total_in + total_out:,} of {budget:,} tokens")
