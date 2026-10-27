"""Stage 5: an independent model call scores each draft. One pass, no loop.

The reviewer only scores. Whether a draft needs attention is decided here in code,
from the scores and the lint, so a model can't wave its own problems through.
"""

from __future__ import annotations

from cti_agent.config import Settings
from cti_agent.llm.client import LLMClient
from cti_agent.llm.steps import outcome_of, traced_call
from cti_agent.models import Hunt, LintFinding, ReviewScores
from cti_agent.stages.analyst import evidence_block
from cti_agent.stages.collector import wrap_untrusted
from cti_agent.trace import Tracer

DIMENSIONS = ("faithful", "kql_correct", "actionable", "calibrated")
ATTENTION_BELOW = 3


def attention_reasons(
    review: ReviewScores | None, lint: list[LintFinding], outcome: str
) -> list[str]:
    reasons = []
    errors = sorted({f.code for f in lint if f.severity == "error"})
    if errors:
        reasons.append("lint errors: " + ", ".join(errors))
    if review is None:
        reasons.append(f"no review ({outcome})")
    else:
        reasons += [
            f"{dim} scored {getattr(review, dim)}"
            for dim in DIMENSIONS
            if getattr(review, dim) < ATTENTION_BELOW
        ]
    return reasons


def review_hunt(
    hunt: Hunt,
    evidence: list[str],
    *,
    client: LLMClient,
    tracer: Tracer,
    settings: Settings,
    system: str,
    actor: str | None = None,
    surroundings: str | None = None,
) -> Hunt:
    lint_lines = [f"- {f.severity}: {f.code}: {f.message}" for f in hunt.lint] or ["- none"]
    user = "\n".join(
        [
            f"Technique: {hunt.technique_id}",
            f"Threat actor named in the report: {actor or 'none'}",
            *evidence_block(evidence, surroundings),
            "",
            "Draft hunt:",
            wrap_untrusted(hunt.draft.model_dump_json(indent=1)),
            "",
            "Deterministic lint findings:",
            *lint_lines,
        ]
    )
    result = traced_call(
        client=client,
        tracer=tracer,
        stage="reviewer",
        step=hunt.draft_id,
        model=settings.review_model,
        system=system,
        user=user,
        schema=ReviewScores,
        max_tokens=settings.analyse_max_output_tokens,
        effort=settings.review_effort,
        refusal_fallback=True,
    )
    outcome = "skipped_budget" if result is None else outcome_of(result)
    review = result.parsed if result is not None else None
    reasons = attention_reasons(review, hunt.lint, outcome)
    return hunt.model_copy(
        update={
            "review": review,
            "review_outcome": outcome,
            "needs_attention": bool(reasons),
            "attention_reasons": reasons,
        }
    )
