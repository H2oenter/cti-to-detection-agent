"""The pipeline end to end: ingest (stages 1-3) and analyse (4-5). The CLI is a thin layer."""

from __future__ import annotations

import json
import secrets
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.attack.attack_index import AttackIndex, AttackLookup
from cti_agent.config import Settings, tlp_block_reason
from cti_agent.feeds.fetch import find_advisory, top_candidates
from cti_agent.feeds.triage import load_watchlist
from cti_agent.feeds.triage import triage as triage_advisory
from cti_agent.inputs import load_source
from cti_agent.llm.client import LLMClient
from cti_agent.llm.prompting import load_prompt
from cti_agent.llm.steps import traced_call
from cti_agent.models import (
    TLP,
    AcceptedItem,
    AnalysisResult,
    Hunt,
    PrepatchExtraction,
    PrepatchResult,
    Provenance,
    RunSummary,
    ValidationResult,
    VulnAdvisory,
)
from cti_agent.outputs.brief_out import (
    brief_facts,
    leadership_summary,
    render_brief,
    render_prepatch_brief,
)
from cti_agent.outputs.kql_out import write_hunts
from cti_agent.outputs.stix_out import build_bundle
from cti_agent.stages.analyst import draft_hunt, schema_text
from cti_agent.stages.collector import ChunkResult, collect, wrap_untrusted
from cti_agent.stages.coverage import (
    check_coverage,
    group_by_tactic,
    load_rules,
    select_for_hunting,
)
from cti_agent.stages.prepatch import (
    advisory_text,
    behaviour_context,
    behaviour_surroundings,
    choose_technique,
    exposure_hunt,
    first_sentence,
    generic_behaviour_context,
    generic_exposure_hunts,
    retire_when,
    target_for,
    technique_from_vector,
    verify_observables,
)
from cti_agent.stages.recheck import recheck
from cti_agent.stages.reviewer import review_hunt, second_review_hunt
from cti_agent.stages.store import has_run_for, save_drafts, save_run, save_run_row
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
    tracer.record(
        stage="validator",
        step="validate",
        outcome="ok",
        detail=f"{len(validation.accepted)} accepted, {len(validation.rejected)} rejected",
    )
    if settings.recheck_indicators:
        validation, checked = recheck(
            validation, client=client, tracer=tracer, settings=settings,
            prompt=load_prompt("recheck"),
        )  # fmt: skip
        if checked:
            _write_json(out_dir / "recheck.json", [asdict(r) for r in checked])
    _write_json(out_dir / "validated.json", validation.model_dump(mode="json")["accepted"])
    write_rejections(out_dir / "rejected.jsonl", validation.rejected)

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
    reviewer2_system = load_prompt("reviewer2").text.replace("{schema}", tables)
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
    techniques = {a.item.attack_id: a for a in accepted if a.item_type == "technique"}
    actor = next((a.item.name for a in accepted if a.item_type == "actor"), None)

    hunts: list[Hunt] = []
    for entry in selected:
        item = techniques[entry.attack_id]
        evidence, surroundings = [item.item.evidence.quote], item.context
        hunt, outcome = draft_hunt(
            entry, evidence, actor,
            client=client, tracer=tracer, settings=settings, system=analyst_system,
            prompt_version=analyst_prompt.version, schema=schema, surroundings=surroundings,
        )  # fmt: skip
        if hunt is None:
            not_drafted.append(f"{entry.attack_id} ({outcome})")
            continue
        reviewed = review_hunt(
            hunt, evidence,
            client=client, tracer=tracer, settings=settings, system=reviewer_system,
            actor=actor, surroundings=surroundings,
        )  # fmt: skip
        reviewed = second_review_hunt(
            reviewed, evidence,
            client=client, tracer=tracer, settings=settings, system=reviewer2_system,
            actor=actor, surroundings=surroundings,
        )  # fmt: skip
        hunts.append(reviewed)

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


# --- Pre-patch: one advisory from the feed inbox -------------------------------------------


def run_prepatch(
    advisory_id: str,
    settings: Settings,
    client: LLMClient,
    *,
    attack: AttackLookup | None = None,
    schema: KqlSchema | None = None,
    now: datetime | None = None,
) -> PrepatchResult:
    found = find_advisory(settings.inbox_dir, advisory_id)
    if found is None:
        raise AnalyseError(
            f"{advisory_id} is not in the inbox; run: cti-agent fetch --id {advisory_id}"
        )
    entry, inbox_day = found
    advisory = VulnAdvisory.model_validate(entry["advisory"])
    triage = entry["triage"]
    # Triage again: an older inbox entry has no tier, and the watchlist may have changed.
    current = triage_advisory(advisory, load_watchlist(settings.watchlist_file))
    watched = current.product
    target = target_for(advisory, watched)

    attack = attack or AttackIndex(*settings.attack_bundles())
    schema = schema or KqlSchema.load(settings.kql_schema_file)
    tables = schema_text(settings.kql_schema_file)
    now = now or datetime.now(UTC)
    first = entry["records"][0]
    run_id = f"{now:%Y%m%dT%H%M%SZ}-{_safe_id(advisory.id)}-{secrets.token_hex(2)}"
    out_dir = settings.out_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=False)
    tracer = Tracer(run_id, out_dir / "trace.jsonl", settings)
    prompt = load_prompt("prepatch")
    provenance = Provenance(
        source_file=advisory.id,
        source_sha256=first["sha256"],
        source_kind="feed",
        source_name=", ".join(sorted({r["source"] for r in entry["records"]})),
        fetched_from=", ".join(r["url"] for r in entry["records"]),
        fetched_at=datetime.fromisoformat(entry["fetched_at"]),
        tlp="CLEAR",
        ingested_at=now,
        run_id=run_id,
        prompt_version=prompt.version,
        model=settings.extract_model,
    )
    tracer.record(
        stage="prepatch", step="load", outcome="ok",
        detail=f"{advisory.id} from {inbox_day.name}; triage {triage}",
    )  # fmt: skip

    text = advisory_text(advisory)
    source = SourceIndex([text])
    extracted = traced_call(
        client=client, tracer=tracer, stage="prepatch", step="extract",
        model=settings.extract_model, system=prompt.text,
        user=f"Advisory {advisory.id}\n\n{wrap_untrusted(text)}",
        schema=PrepatchExtraction, max_tokens=settings.extract_max_output_tokens,
        effort=settings.extract_effort,
    )  # fmt: skip
    extraction = extracted.parsed if extracted is not None else None
    observables, rejected = verify_observables(extraction, source) if extraction else ([], [])

    retire = retire_when(advisory, target.name, now, names_approximate=watched is None)
    technique = choose_technique(
        extraction, source, attack, technique_from_vector(advisory.cvss_vector)
    )
    if watched:
        hunts = [exposure_hunt(advisory, watched, technique.attack_id, schema, retire)]
        facts = behaviour_context(advisory, watched, current.signals)
    else:
        hunts = generic_exposure_hunts(advisory, target, technique.attack_id, schema, retire)
        facts = generic_behaviour_context(advisory, target, current.reasons)

    analyst_prompt, reviewer_prompt = load_prompt("analyst"), load_prompt("reviewer")
    evidence = [o.evidence.quote for o in observables] or [first_sentence(advisory.description)]
    surroundings = behaviour_surroundings(advisory, extraction)
    hunt, outcome = None, None
    if watched or observables:
        hunt, outcome = draft_hunt(
            technique, evidence, None,
            client=client, tracer=tracer, settings=settings,
            system=analyst_prompt.text.replace("{schema}", tables),
            prompt_version=analyst_prompt.version, schema=schema, kind="behaviour",
            surroundings=surroundings,
            extra=facts,
        )  # fmt: skip
    else:
        # A product with no known process names and nothing verifiable in the advisory would
        # get a guessed hunt; better none, and the exposure queries alone.
        outcome = "no verified observable to hunt for, and the product isn't on the watchlist"
    if hunt is not None:
        hunt = review_hunt(
            hunt, evidence,
            client=client, tracer=tracer, settings=settings,
            system=reviewer_prompt.text.replace("{schema}", tables),
            surroundings=surroundings, facts=facts,
        )  # fmt: skip
        hunt = second_review_hunt(
            hunt, evidence,
            client=client, tracer=tracer, settings=settings,
            system=load_prompt("reviewer2").text.replace("{schema}", tables),
            surroundings=surroundings, facts=facts,
        )  # fmt: skip
        hunts.append(
            hunt.model_copy(
                update={"retire_when": retire, "draft_id": f"{_safe_id(advisory.id)}-behaviour"}
            )
        )

    result = PrepatchResult(
        run_id=run_id,
        advisory=advisory,
        product=target.name,
        tier=current.tier,
        signals=current.reasons,
        extraction=extraction,
        observables=observables,
        rejected_observables=rejected
        + ([] if hunt else [f"behaviour hunt not drafted: {outcome}"]),
        hunts=hunts,
        retire_when=retire,
    )
    write_hunts(hunts, out_dir / "hunts")
    _write_json(out_dir / "prepatch.json", result.model_dump(mode="json"))
    _write_json(out_dir / "provenance.json", provenance.model_dump(mode="json"))
    (out_dir / "brief.md").write_text(render_prepatch_brief(result, provenance), encoding="utf-8")
    planned = hunt is not None or not (watched or observables)  # no behaviour hunt by design
    save_run_row(
        settings.db_path, provenance, "complete" if planned and hunts else "partial",
        {"hunts": len(hunts), "advisory": advisory.id},
    )  # fmt: skip
    save_drafts(settings.db_path, run_id, hunts)
    return result


def run_prepatch_top(
    n: int, settings: Settings, client: LLMClient, **kwargs
) -> tuple[list[PrepatchResult], list[str]]:
    """Pre-patch hunts for the n highest-ranked advisories of the newest fetch. An advisory
    that already has a pre-patch run is skipped. Returns (results, skipped IDs)."""
    results, skipped = [], []
    for advisory_id in top_candidates(settings.inbox_dir, n):
        if has_run_for(settings.db_path, advisory_id):
            skipped.append(advisory_id)
            continue
        results.append(run_prepatch(advisory_id, settings, client, **kwargs))
    return results, skipped


def _safe_id(identifier: str) -> str:
    return "".join(c if c.isalnum() or c == "-" else "_" for c in identifier)
