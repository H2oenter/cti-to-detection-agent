"""cti-agent: the command-line entry point.

Every command is read-only except `publish --apply`, which is the only path that
sends data anywhere (design rule 5).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import click
import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from cti_agent import __version__
from cti_agent.audit import AuditChainBroken, AuditLog, current_actor
from cti_agent.config import Settings
from cti_agent.evaluation.gold import GoldError
from cti_agent.evaluation.injection import run_injection_suite
from cti_agent.evaluation.runner import EvalError, gold_markdown, run_gold_eval, write_results
from cti_agent.feeds.fetch import SOURCES as FEED_SOURCES
from cti_agent.feeds.fetch import parse_since, run_fetch
from cti_agent.inputs import InputError
from cti_agent.llm.client import (
    AnthropicClient,
    FatalLLMError,
    FixtureMissing,
    LLMClient,
    RecordingClient,
    ReplayClient,
)
from cti_agent.models import AnalysisResult
from cti_agent.outputs.sentinel_upload import (
    BATCH_SIZE,
    BatchResult,
    PublishError,
    endpoint,
    plan_sentinel,
    send,
    token_provider,
    write_dry_run,
)
from cti_agent.pipeline import (
    AnalyseError,
    IngestBlocked,
    IngestResult,
    run_analyse,
    run_ingest,
    run_prepatch,
)
from cti_agent.review_ui import run_review
from cti_agent.stages.gate import Gate, GateError
from cti_agent.stages.store import mark_published
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


@app.callback()
def _setup() -> None:
    # Report text can hold characters a legacy Windows code page can't print (pypdf emits
    # U+FFFD for unmapped glyphs). Print a replacement instead of crashing mid-run.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


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
    client = _make_client(settings, replay, record)
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
    _replay_note(replay, record)


def _make_client(settings: Settings, replay: Path | None, record: Path | None) -> LLMClient:
    """--replay: offline. --record: live, saving every response. Both, with one folder:
    replay what is recorded and call the API only for what is missing, recording it."""
    if replay and record:
        if replay.resolve() != record.resolve():
            raise typer.BadParameter("to fill gaps, give --replay and --record the same folder")
        return ReplayClient(replay, fallback=_live_client(settings))
    if replay:
        return ReplayClient(replay)
    client = _live_client(settings)
    return RecordingClient(client, record) if record else client


def _live_client(settings: Settings) -> AnthropicClient:
    key = settings.anthropic_api_key
    return AnthropicClient(
        api_key=key.get_secret_value() if key else None,
        workspace_id=settings.anthropic_workspace_id,
    )


def _replay_note(replay: Path | None, record: Path | None) -> None:
    if replay and record:
        console.print(
            "[dim]Recorded responses were replayed; missing ones were fetched live and "
            "recorded.[/dim]"
        )
    elif replay:
        console.print(
            "[dim]Replayed recorded responses: token counts and cost are from the original "
            "run. Nothing was sent to the API.[/dim]"
        )


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
    since: Annotated[str, typer.Option(help="Look-back window: 90m, 24h, 7d.")] = "24h",
    source: Annotated[str, typer.Option(help="Comma-separated: kev, osv, cve.")] = "kev,osv,cve",
    cve_id: Annotated[
        list[str] | None, typer.Option("--id", help="Also fetch this CVE record. Repeatable.")
    ] = None,
    show_all: Annotated[
        bool, typer.Option("--all", help="List every advisory, not just hunt now and hunt soon.")
    ] = False,
) -> None:
    """Pull fresh advisories from the allowlisted feeds and triage them (no LLM)."""
    try:
        window = parse_since(since)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    wanted = tuple(s.strip() for s in source.split(",") if s.strip())
    if unknown := set(wanted) - set(FEED_SOURCES):
        raise typer.BadParameter(f"unknown source(s): {', '.join(sorted(unknown))}")
    settings = Settings()
    result = run_fetch(settings, since=window, sources=wanted, cve_ids=tuple(cve_id or ()))

    # result.triaged comes ranked: hunt now, hunt soon, watch, other.
    rows = [t for t in result.triaged if t.passed or show_all]
    table = Table(title=f"Triage: last {since}", title_justify="left")
    for col in ("#", "Advisory", "Product", "Tier", "Why", "CVSS", "KEV due", "Fixed in"):
        table.add_column(col, overflow="fold")
    tier_style = {"hunt now": "bold red", "hunt soon": "yellow"}
    for n, t in enumerate(rows, start=1):
        adv = t.advisory
        fixed = sorted({r.fixed for p in adv.affected for r in p.ranges if r.fixed})
        product = next((f"{p.vendor or p.ecosystem or ''} {p.product}".strip()
                        for p in adv.affected), "")  # fmt: skip
        style = tier_style.get(t.tier, "")
        table.add_row(
            str(n),
            adv.id + (" [bold red](zero-day)[/bold red]" if t.zero_day else ""),
            product + (" [cyan](watchlist)[/cyan]" if t.product else ""),
            f"[{style}]{t.tier}[/{style}]" if style else t.tier,
            "; ".join(t.reasons),
            str(adv.cvss_score or ""),
            str(adv.kev_due_date or ""),
            ", ".join(fixed[:4]) + ("…" if len(fixed) > 4 else ""),
        )
    console.print(table)
    tiers = Counter(t.tier for t in result.triaged)
    zero_days = sum(t.zero_day for t in result.triaged)
    console.print(
        f"{len(result.triaged)} advisories: [bold]{tiers['hunt now']} hunt now[/bold], "
        f"{tiers['hunt soon']} hunt soon ({zero_days} zero-day), {tiers['watch']} watch; "
        f"{result.malicious_packages} malicious-package reports skipped; "
        f"{len(result.requested)} GET requests, all to allowlisted hosts."
    )
    if tiers["hunt now"] + tiers["hunt soon"]:
        console.print("Draft pre-patch hunts for the top ones: cti-agent prepatch --top 5")
    for note in result.notes:
        console.print(f"[yellow]note:[/yellow] {note}")
    for error in result.errors[:5]:
        console.print(f"[yellow]skipped:[/yellow] {error}")
    if len(result.errors) > 5:
        console.print(f"[yellow]…and {len(result.errors) - 5} more skipped[/yellow]")
    console.print(f"Inbox: {result.inbox}")


@app.command()
def analyse(
    run_id: str,
    replay: Annotated[
        Path | None, typer.Option(help="Replay recorded model responses from this folder.")
    ] = None,
    record: Annotated[
        Path | None, typer.Option(help="Save model responses to this folder as test fixtures.")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Redo an analysed run.")] = False,
) -> None:
    """Stages 4-5: ATT&CK coverage, KQL drafts, reviewer scores and the brief."""
    settings = Settings()
    client = _make_client(settings, replay, record)
    try:
        analysis = run_analyse(run_id, settings, client, force=force)
    except IngestBlocked as exc:
        console.print(f"[red]Blocked:[/red] {exc}")
        raise typer.Exit(code=2) from None
    except (AnalyseError, FileNotFoundError, FixtureMissing) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    except FatalLLMError as exc:
        console.print(f"[red]Model call failed, run stopped:[/red] {exc}")
        raise typer.Exit(code=3) from None
    _print_analysis(analysis, settings.out_dir / run_id)
    _replay_note(replay, record)


def _print_analysis(analysis: AnalysisResult, out_dir: Path) -> None:
    states = Counter(e.state for e in analysis.coverage)
    console.print(
        f"\n[bold]Coverage[/bold] {len(analysis.coverage)} techniques: "
        f"[green]{states['covered']} covered[/green], [yellow]{states['partial']} partial[/yellow],"
        f" [red]{states['gap']} gaps[/red], {states['not_applicable']} mobile (not huntable)"
    )
    table = Table(title="Draft hunts (pending human review)", title_justify="left")
    for col in ("Technique", "Title", "Lint", "Review F/K/A/C", "Attention"):
        table.add_column(col, overflow="fold")
    for h in analysis.hunts:
        errors = [f.code for f in h.lint if f.severity == "error"]
        warnings = [f.code for f in h.lint if f.severity == "warning"]
        lint = (
            ", ".join(errors) if errors else (f"ok ({', '.join(warnings)})" if warnings else "ok")
        )
        r = h.review
        scores = (
            f"{r.faithful}/{r.kql_correct}/{r.actionable}/{r.calibrated}" if r else h.review_outcome
        )
        flag = "[red]" + "; ".join(h.attention_reasons) + "[/red]" if h.needs_attention else ""
        table.add_row(h.technique_id, h.draft.title, lint, scores, flag)
    console.print(table)
    if analysis.not_drafted:
        console.print(f"Gaps not drafted this run: {', '.join(analysis.not_drafted)}")
    console.print(f"\n[bold]For leadership[/bold] ({analysis.summary_source}):")
    console.print(analysis.leadership_summary)
    console.print(f"\nBrief: {out_dir / 'brief.md'}   Hunts: {out_dir / 'hunts'}")


@app.command()
def prepatch(
    advisory_id: Annotated[str, typer.Argument(help="CVE or GHSA ID from the fetch inbox.")],
    replay: Annotated[
        Path | None, typer.Option(help="Replay recorded model responses from this folder.")
    ] = None,
    record: Annotated[
        Path | None, typer.Option(help="Save model responses to this folder as test fixtures.")
    ] = None,
) -> None:
    """Exposure query and behaviour hunt for one advisory, to use until it's patched."""
    settings = Settings()
    client = _make_client(settings, replay, record)
    try:
        result = run_prepatch(advisory_id, settings, client)
    except (AnalyseError, FileNotFoundError, FixtureMissing) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    except FatalLLMError as exc:
        console.print(f"[red]Model call failed, run stopped:[/red] {exc}")
        raise typer.Exit(code=3) from None

    adv = result.advisory
    console.print(f"\n[bold]{adv.id}[/bold] {adv.title or ''}  ({result.product})")
    console.print(f"Why: {'; '.join(result.signals)}")
    console.print(
        f"Observables verified against the advisory text: {len(result.observables)}"
        + (f", rejected: {len(result.rejected_observables)}" if result.rejected_observables else "")
    )
    table = Table(title="Pre-patch hunts (pending human review)", title_justify="left")
    for col in ("Kind", "Title", "By", "Lint", "Review F/K/A/C", "Attention"):
        table.add_column(col, overflow="fold")
    for h in result.hunts:
        errors = [f.code for f in h.lint if f.severity == "error"]
        r = h.review
        table.add_row(
            h.kind,
            h.draft.title,
            h.model,
            ", ".join(errors) or "ok",
            f"{r.faithful}/{r.kql_correct}/{r.actionable}/{r.calibrated}" if r else "n/a (code)",
            "[red]" + "; ".join(h.attention_reasons) + "[/red]" if h.needs_attention else "",
        )
    console.print(table)
    console.print(f"[bold]{result.retire_when}[/bold]")
    out_dir = settings.out_dir / result.run_id
    console.print(f"Brief: {out_dir / 'brief.md'}   Hunts: {out_dir / 'hunts'}")
    _replay_note(replay, record)


def _audit_log(settings: Settings) -> AuditLog:
    return AuditLog(settings.out_dir / "audit.jsonl", settings.db_path)


@app.command()
def review(
    run_id: str,
    item: Annotated[
        str | None, typer.Option(help="Decide one item without the interactive loop.")
    ] = None,
    approve: Annotated[bool, typer.Option("--approve", help="With --item.")] = False,
    reject: Annotated[bool, typer.Option("--reject", help="With --item; needs --reason.")] = False,
    reason: Annotated[str | None, typer.Option(help="Why the item is rejected.")] = None,
    include_decided: Annotated[
        bool, typer.Option("--all", help="Show items that already have a decision too.")
    ] = False,
    reviewer: Annotated[
        str | None,
        typer.Option(help="Name for the audit log. Default: CTI_AGENT_REVIEWER or OS user."),
    ] = None,
) -> None:
    """Stage 6: approve, reject or edit each hunt and STIX object. Every decision is audited."""
    settings = Settings()
    try:
        gate = Gate(settings, run_id, current_actor(reviewer), _audit_log(settings))
    except AuditChainBroken as exc:
        console.print(
            f"[red]The audit log failed verification, so no decisions can be made:[/red] {exc}"
        )
        raise typer.Exit(code=4) from None
    except GateError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None

    if item:
        if approve == reject:
            raise typer.BadParameter("with --item, pass exactly one of --approve or --reject")
        try:
            gate.decide(gate.item(item), "approve" if approve else "reject", reason)
        except GateError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from None
        console.print(f"{item}: {'approved' if approve else 'rejected'} by {gate.actor}")
        return

    if not gate.pending(include_decided):
        console.print("Nothing waiting for review. Pass --all to see decided items again.")
        return
    counts = run_review(
        gate,
        console,
        ask=lambda prompt, keys: typer.prompt(
            prompt, type=click.Choice(keys, case_sensitive=True), show_choices=False
        ),
        ask_text=lambda prompt: typer.prompt(prompt),
        edit=lambda text, extension: click.edit(text, extension=extension),
        include_decided=include_decided,
    )
    console.print(
        f"\n{counts['approved']} approved, {counts['rejected']} rejected, "
        f"{counts['skipped']} skipped; {len(gate.pending())} still waiting."
    )
    console.print(
        f"Approved items: {gate.out_dir / 'approved'}   Audit: cti-agent audit --run {run_id}"
    )


@app.command(name="audit")
def audit_(
    run: Annotated[str | None, typer.Option(help="Only this run.")] = None,
    verify: Annotated[
        bool, typer.Option("--verify", help="Exit non-zero if the hash chain is broken.")
    ] = False,
) -> None:
    """Show the audit log and check its hash chain."""
    log = _audit_log(Settings())
    table = Table(title="Audit log" + (f": {run}" if run else ""), title_justify="left")
    for col in ("Time (UTC)", "Actor", "Action", "Item", "Decision", "Reason", "Hash"):
        table.add_column(col, overflow="fold")
    for row in log.entries(run):
        decision = (row["decision"] or "") + (" (bulk)" if row["bulk"] else "")
        table.add_row(
            row["ts"][:19].replace("T", " "),
            row["actor"],
            row["action"],
            row["item_ref"] or row["run_id"],
            decision,
            row["reason"] or "",
            row["hash"][:12],
        )
    console.print(table)
    try:
        log.verify()
        console.print(
            "[green]Hash chain verified: no line was changed, removed or reordered.[/green]"
        )
    except AuditChainBroken as exc:
        console.print(f"[red]Hash chain broken: {exc}[/red]")
        if verify:
            raise typer.Exit(code=4) from None


@app.command()
def publish(
    run_id: str,
    target: Annotated[str, typer.Option(help="Only sentinel for now.")] = "sentinel",
    apply: Annotated[
        bool, typer.Option("--apply", help="Actually send. Default is a dry run.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", help="With --apply: don't ask to confirm.")] = False,
    use_az_login: Annotated[
        bool, typer.Option("--use-az-login", help="With --apply: publish as you (after az login).")
    ] = False,
    reviewer: Annotated[str | None, typer.Option(help="Name for the audit log.")] = None,
) -> None:
    """Upload approved STIX objects to Sentinel. A dry run that sends nothing unless --apply."""
    if target != "sentinel":
        console.print(
            f"[yellow]{target} publishing is a stretch goal and isn't built yet.[/yellow]"
        )
        raise typer.Exit(code=1)
    settings = Settings()
    log = _audit_log(settings)
    try:
        gate = Gate(settings, run_id, current_actor(reviewer), log)
        plan = plan_sentinel(gate)
    except AuditChainBroken as exc:
        console.print(
            f"[red]The audit log failed verification, so nothing is published:[/red] {exc}"
        )
        raise typer.Exit(code=4) from None
    except (GateError, PublishError) as exc:
        console.print(f"[red]Not publishing:[/red] {exc}")
        raise typer.Exit(code=2) from None

    counts = ", ".join(f"{n} {kind}" for kind, n in sorted(plan.counts().items()))
    console.print(f"\n[bold]Approved for Sentinel:[/bold] {len(plan.objects)} objects ({counts})"
                  f" in {len(plan.batches)} request(s) of up to {BATCH_SIZE}")  # fmt: skip
    for kind, n in Counter(s["type"] for s in plan.skipped).items():
        console.print(f"[yellow]Left out:[/yellow] {n} {kind} (the upload API doesn't accept them)")
    if plan.hunts_not_uploaded:
        hunts_dir = gate.out_dir / "approved" / "hunts"
        console.print(
            f"{plan.hunts_not_uploaded} approved hunt(s) stay in {hunts_dir} for your change "
            "process; they aren't uploaded."
        )

    if not apply:
        folder = write_dry_run(
            plan, gate.out_dir, settings.sentinel_workspace_id, datetime.now(UTC)
        )
        log.append(
            run_id=run_id, actor=gate.actor, action="publish", decision="dry-run",
            detail={"target": "sentinel", "objects": len(plan.objects),
                    "requests": len(plan.batches), "folder": folder.name},
        )  # fmt: skip
        first = json.loads((folder / "request-001.json").read_text(encoding="utf-8"))
        console.print(f"\nPOST {json.loads((folder / 'manifest.json').read_text('utf-8'))['url']}")
        console.print_json(json.dumps({**first, "stixobjects": first["stixobjects"][:2]}))
        console.print(
            f"[dim]…{len(first['stixobjects']) - 2} more objects in request-001.json[/dim]"
        )
        console.print(f"\n[bold]Dry run: nothing was sent.[/bold] Requests and manifest: {folder}")
        console.print("To upload, run again with --apply using the publish identity.")
        return

    if not settings.sentinel_workspace_id:
        console.print("[red]--apply needs SENTINEL_WORKSPACE_ID.[/red]")
        raise typer.Exit(code=2)
    try:
        token = token_provider(settings, use_az_login)
        endpoint(settings.sentinel_workspace_id)
    except PublishError as exc:
        console.print(f"[red]Not publishing:[/red] {exc}")
        raise typer.Exit(code=2) from None
    if not yes and not typer.confirm(
        f"Upload {len(plan.objects)} objects in {len(plan.batches)} request(s) to workspace "
        f"{settings.sentinel_workspace_id}?",
        default=False,
    ):
        raise typer.Exit(code=1)

    def record(result: BatchResult) -> None:
        log.append(
            run_id=run_id, actor=gate.actor, action="publish_batch",
            decision="sent" if not result.failed else "partly rejected",
            detail={"target": "sentinel", "batch": result.index, "status": result.status,
                    "attempts": result.attempts, "objects": result.object_ids,
                    "failed": result.failed},
        )  # fmt: skip
        mark_published(settings.db_path, run_id, result)

    try:
        results = send(plan, settings.sentinel_workspace_id, token, on_batch=record)
    except PublishError as exc:
        log.append(run_id=run_id, actor=gate.actor, action="publish", decision="failed",
                   reason=str(exc), detail={"target": "sentinel"})  # fmt: skip
        console.print(f"[red]Stopped:[/red] {exc}")
        raise typer.Exit(code=3) from None
    failed = [f for r in results for f in r.failed]
    log.append(
        run_id=run_id, actor=gate.actor, action="publish", decision="applied",
        detail={"target": "sentinel", "objects": len(plan.objects), "failed": len(failed)},
    )  # fmt: skip
    console.print(f"[green]Uploaded {len(plan.objects) - len(failed)} objects[/green]; "
                  f"{len(failed)} rejected by Sentinel (see the audit log).")  # fmt: skip


@app.command(name="eval")
def eval_(
    suite: Annotated[str, typer.Option(help="gold, injection or all.")] = "all",
    gold: Annotated[Path, typer.Option(help="Folder of gold label files.")] = Path("eval/gold"),
    injection: Annotated[Path, typer.Option(help="Injection suite folder.")] = Path(
        "eval/injection"
    ),
    replay: Annotated[
        Path | None, typer.Option(help="Replay recorded model responses from this folder.")
    ] = None,
    record: Annotated[
        Path | None, typer.Option(help="Save model responses to this folder.")
    ] = None,
    results: Annotated[Path, typer.Option(help="Where to write results.")] = Path("eval/results"),
    write: Annotated[bool, typer.Option(help="Write the results files.")] = True,
) -> None:
    """Score the pipeline against the gold set, and run the injection suite."""
    if suite not in ("gold", "injection", "all"):
        raise typer.BadParameter("--suite is gold, injection or all")
    settings = Settings()
    client = _make_client(settings, replay, record)
    gold_result = injection_result = None
    try:
        if suite in ("gold", "all"):
            gold_result = run_gold_eval(
                settings, client, gold, replayed=bool(replay) and not record
            )
        if suite in ("injection", "all"):
            injection_result = run_injection_suite(settings, client, injection)
    except (EvalError, GoldError, FixtureMissing, InputError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    except FatalLLMError as exc:
        console.print(f"[red]Model call failed, eval stopped:[/red] {exc}")
        raise typer.Exit(code=3) from None

    if gold_result:
        console.print(Markdown(gold_markdown(gold_result)))
        for s in gold_result.scores:
            missed = s.false_negatives["indicators"] + s.false_negatives["techniques"]
            extra = s.false_positives["indicators"] + s.false_positives["techniques"]
            if missed or extra:
                console.print(f"[dim]{s.report_id}: missed {missed or 'none'}; "
                              f"not in gold {extra or 'none'}[/dim]")  # fmt: skip
    if injection_result:
        console.print(Markdown(injection_result.markdown()))
    if write:
        results.mkdir(parents=True, exist_ok=True)
        if gold_result:
            path = write_results(
                gold_result, results, injection_result.as_dict() if injection_result else None
            )
        else:
            path = results / f"{injection_result.run_at:%Y-%m-%d}-injection.md"
            path.write_text(injection_result.markdown(), encoding="utf-8")
            path.with_suffix(".json").write_text(
                json.dumps(injection_result.as_dict(), indent=2) + "\n", encoding="utf-8"
            )
        console.print(f"Results: {path}")
    _replay_note(replay, record)
    if injection_result and not injection_result.passed:
        raise typer.Exit(code=1)


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
