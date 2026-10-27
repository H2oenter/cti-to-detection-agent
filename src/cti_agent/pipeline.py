"""The pipeline end to end: ingest (stages 1-3) and analyse (4-5). The CLI is a thin layer."""

from __future__ import annotations

import json
import secrets
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.attack.attack_index import AttackIndex, AttackLookup
from cti_agent.config import Settings, tlp_block_reason
from cti_agent.inputs import load_source
from cti_agent.llm.client import LLMClient
from cti_agent.llm.prompting import load_prompt
from cti_agent.models import (
    TLP,
    AcceptedItem,
    AnalysisResult,
    Hunt,
    Provenance,
    RunSummary,
    ValidationResult,
)
from cti_agent.outputs.brief_out import brief_facts, leadership_summary, render_brief
from cti_agent.outputs.kql_out import write_hunts
from cti_agent.outputs.stix_out import build_bundle
from cti_agent.stages.analyst import draft_hunt, schema_text
from cti_agent.stages.collector import ChunkResult, collect
from cti_agent.stages.coverage import (
    check_coverage,
    group_by_tactic,
    load_rules,
    select_for_hunting,
)
from cti_agent.stages.reviewer import review_hunt
from cti_agent.stages.store import save_drafts, save_run
from cti_agent.stages.validator import Allowlist, validate, write_rejections
from cti_agent.trace import Tracer
from cti_agent.util.kql_lint import KqlSchema
from cti_agent.util.normalise import SourceIndex


class IngestBlocked(Exception):
    """A policy (such as the TLP gate) stopped the run before any model call."""


@dataclass
class IngestResult:
    run_id: str
    out_dir: Path
    summary: RunSummary
    validation: ValidationResult
    chunks: list[ChunkResult]


def new_run_id(now: datetime, source_sha256: str) -> str:
    return f"{now:%Y%m%dT%H%M%SZ}-{source_sha256[:8]}-{secrets.token_hex(2)}"


def run_ingest(
    path: Path,
    tlp: TLP,
    settings: Settings,
    client: LLMClient,
    *,
    attack: AttackLookup | None = None,
    now: datetime | None = None,
    run_id: str | None = None,
) -> IngestResult:
    if reason := tlp_block_reason(tlp, settings):
        raise IngestBlocked(reason)

    # Load everything local first, so a missing file fails before any tokens are spent.
    doc = load_source(path)
    attack = attack or AttackIndex(*settings.attack_bundles())
    allowlist = Allowlist.load(settings.allowlist_file)
    prompt = load_prompt("collector")

    now = now or datetime.now(UTC)
    run_id = run_id or new_run_id(now, doc.sha256)
    out_dir = settings.out_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=False)
    tracer = Tracer(run_id, out_dir / "trace.jsonl", settings)
    provenance = Provenance(
        source_file=doc.path.name,  # name only: local paths stay out of shareable output
        source_sha256=doc.sha256,
        tlp=tlp,
        ingested_at=now,
        run_id=run_id,
        prompt_version=prompt.version,
        model=settings.extract_model,
    )
    tracer.record(
        stage="ingest",
        step="load",
        outcome="ok",
        detail=f"{doc.media_type}, {len(doc.pages)} pp; ATT&CK: {attack.description}",
    )

    chunks = collect(doc.text, client=client, tracer=tracer, settings=settings, prompt=prompt)
    _write_json(
        out_dir / "extraction.raw.json",
        [
            {
                "chunk": c.index,
                "outcome": c.outcome,
                "detail": c.detail,
                "extraction": c.extraction.model_dump(mode="json") if c.extraction else None,
            }
            for c in chunks
        ],
    )

    extractions = [c.extraction for c in chunks if c.extraction is not None]
    validation = validate(extractions, SourceIndex(doc.pages), attack, allowlist)
    _write_json(out_dir / "validated.json", validation.model_dump(mode="json")["accepted"])
    write_rejections(out_dir / "rejected.jsonl", validation.rejected)
    tracer.record(
        stage="validator",
        step="validate",
        outcome="ok",
        detail=f"{len(validation.accepted)} accepted, {len(validation.rejected)} rejected",
    )

    title = next((e.report_title for e in extractions if e.report_title.strip()), doc.path.stem)
    bundle = build_bundle(validation, provenance, title, attack)
    (out_dir / "bundle.json").write_text(bundle.serialize(pretty=True), encoding="utf-8")

    summary = _summarise(run_id, provenance, chunks, validation, tracer)
    stored = save_run(settings.db_path, provenance, summary, bundle)
    tracer.record(stage="store", step="sqlite+stix", outcome="ok", detail=f"{stored} objects")
    _write_json(out_dir / "provenance.json", provenance.model_dump(mode="json"))
    _write_json(out_dir / "run_summary.json", summary.model_dump(mode="json"))
    return IngestResult(run_id, out_dir, summary, validation, chunks)


def _summarise(run_id, provenance, chunks, validation, tracer) -> RunSummary:
    outcomes = [c.outcome for c in chunks]
    done = outcomes.count("ok")
    if done == len(chunks):
        status, stop = "complete", None
    else:
        status = "partial" if done else "failed"
        stop = next(
            (o for o in ("skipped_budget", "refused", "error", "truncated", "invalid_output")
             if o in outcomes),
            None,
        )  # fmt: skip
    return RunSummary(
        run_id=run_id,
        source_file=provenance.source_file,
        status=status,
        stop_reason={"skipped_budget": "budget", "refused": "refusal"}.get(stop, stop),
        chunks_total=len(chunks),
        chunks_done=done,
        chunks_refused=outcomes.count("refused"),
        accepted_counts=validation.accepted_counts(),
        rejected_counts=validation.rejected_counts(),
        input_tokens=tracer.input_tokens,
        output_tokens=tracer.output_tokens,
        est_cost_usd=round(tracer.cost_usd, 6),
    )


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# --- Stages 4-5: analyse ----------------------------------------------------------------


class AnalyseError(Exception):
    pass


def run_analyse(
    run_id: str,
    settings: Settings,
    client: LLMClient,
    *,
    attack: AttackLookup | None = None,
    schema: KqlSchema | None = None,
    force: bool = False,
) -> AnalysisResult:
    out_dir = settings.out_dir / run_id
    if not (out_dir / "validated.json").exists():
        raise AnalyseError(f"no ingest output for run {run_id} in {settings.out_dir}")
    if (out_dir / "analysis.json").exists() and not force:
        raise AnalyseError(f"run {run_id} is already analysed; pass --force to redo it")

    provenance = Provenance.model_validate_json((out_dir / "provenance.json").read_text("utf-8"))
    # Evidence quotes are report text and go to a model again, so the TLP gate applies again.
    if reason := tlp_block_reason(provenance.tlp, settings):
        raise IngestBlocked(reason)
    accepted = [
        AcceptedItem.model_validate(a)
        for a in json.loads((out_dir / "validated.json").read_text("utf-8"))
    ]
    bundle = json.loads((out_dir / "bundle.json").read_text("utf-8"))
    title = next((o["name"] for o in bundle["objects"] if o["type"] == "report"), run_id)

    attack = attack or AttackIndex(*settings.attack_bundles())
    schema = schema or KqlSchema.load(settings.kql_schema_file)
    tables = schema_text(settings.kql_schema_file)
    analyst_prompt, reviewer_prompt = load_prompt("analyst"), load_prompt("reviewer")
    analyst_system = analyst_prompt.text.replace("{schema}", tables)
    reviewer_system = reviewer_prompt.text.replace("{schema}", tables)
    tracer = Tracer(run_id, out_dir / "trace.jsonl", settings)

    coverage = check_coverage(accepted, attack, load_rules(settings.rules_file))
    selected, not_drafted = select_for_hunting(coverage, settings.max_hunts_per_run)
    states = {s: sum(e.state == s for e in coverage) for s in ("covered", "partial", "gap")}
    tracer.record(
        stage="analyst",
        step="coverage",
        outcome="ok",
        detail=f"{len(coverage)} techniques, {states}; drafting {len(selected)}",
    )
    evidence = {
        a.item.attack_id: [a.item.evidence.quote] for a in accepted if a.item_type == "technique"
    }
    actor = next((a.item.name for a in accepted if a.item_type == "actor"), None)

    hunts: list[Hunt] = []
    for entry in selected:
        hunt, outcome = draft_hunt(
            entry, evidence[entry.attack_id], actor,
            client=client, tracer=tracer, settings=settings, system=analyst_system,
            prompt_version=analyst_prompt.version, schema=schema,
        )  # fmt: skip
        if hunt is None:
            not_drafted.append(f"{entry.attack_id} ({outcome})")
            continue
        hunts.append(
            review_hunt(
                hunt,
                evidence[entry.attack_id],
                client=client,
                tracer=tracer,
                settings=settings,
                system=reviewer_system,
            )
        )

    analysis = AnalysisResult(
        run_id=run_id,
        actor=actor,
        tactics=group_by_tactic(coverage),
        coverage=coverage,
        hunts=hunts,
        not_drafted=not_drafted,
    )
    indicator_count = sum(a.item_type == "indicator" for a in accepted)
    facts = brief_facts(analysis, title, indicator_count)
    summary, source = leadership_summary(
        facts, client=client, tracer=tracer, settings=settings,
        system=load_prompt("brief").text,
    )  # fmt: skip
    analysis = analysis.model_copy(update={"leadership_summary": summary, "summary_source": source})

    hunts_dir = out_dir / "hunts"
    if hunts_dir.exists():
        shutil.rmtree(hunts_dir)  # generated by an earlier --force run; rebuilt below
    write_hunts(hunts, hunts_dir)
    _write_json(out_dir / "analysis.json", analysis.model_dump(mode="json"))
    (out_dir / "brief.md").write_text(
        render_brief(analysis, facts, provenance, attack.description), encoding="utf-8"
    )
    save_drafts(settings.db_path, run_id, hunts)
    return analysis
