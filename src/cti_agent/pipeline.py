"""Stages 1-3 end to end: load, collect, validate, store. The CLI is a thin layer over this."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.attack.attack_index import AttackIndex, AttackLookup
from cti_agent.config import Settings, tlp_block_reason
from cti_agent.inputs import load_source
from cti_agent.llm.client import LLMClient
from cti_agent.llm.prompting import load_prompt
from cti_agent.models import TLP, Provenance, RunSummary, ValidationResult
from cti_agent.outputs.stix_out import build_bundle
from cti_agent.stages.collector import ChunkResult, collect
from cti_agent.stages.store import save_run
from cti_agent.stages.validator import Allowlist, validate, write_rejections
from cti_agent.trace import Tracer
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
    attack = attack or AttackIndex(settings.attack_bundle)
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
        stage="ingest", step="load", outcome="ok", detail=f"{doc.media_type}, {len(doc.pages)} pp"
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
