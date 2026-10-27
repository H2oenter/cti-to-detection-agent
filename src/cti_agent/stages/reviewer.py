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


def second_opinion_reasons(
    first: ReviewScores | None,
    second: ReviewScores | None,
    outcome: str,
    answered_by: str | None,
    first_model: str,
) -> list[str]:
    """What the second review adds to the attention list. The first reviewer's own reasons
    stand as they are; a dimension it already flagged isn't flagged twice."""
    if second is None:
        return [f"no second review ({outcome})"]
    reasons = []
    if answered_by == first_model:  # a refusal fallback can land on the first reviewer's model
        reasons.append(f"second review answered by {answered_by}, the same model as the first")
    for dim in DIMENSIONS:
        a = getattr(first, dim) if first else None
        b = getattr(second, dim)
        if a is not None and a < ATTENTION_BELOW:
            continue
        if b < ATTENTION_BELOW:
            reasons.append(f"second reviewer scored {dim} {b}" + (f" (first: {a})" if a else ""))
        elif a is not None and abs(a - b) >= 2:
            reasons.append(f"reviewers disagree on {dim}: {a} vs {b}")
    return reasons


def review_user(
    hunt: Hunt,
    evidence: list[str],
    actor: str | None = None,
    surroundings: str | None = None,
    facts: str | None = None,
) -> str:
    """What each reviewer is shown. The second sees exactly what the first saw, and not the
    first's scores."""
    lint_lines = [f"- {f.severity}: {f.code}: {f.message}" for f in hunt.lint] or ["- none"]
    return "\n".join(
        [
            f"Technique: {hunt.technique_id}",
            f"Threat actor named in the report: {actor or 'none'}",
            *(
                [f"Facts the analyst was given from structured feed fields:\n{facts}"]
                if facts
                else []
            ),
            *evidence_block(evidence, surroundings),
            "",
            "Draft hunt:",
            wrap_untrusted(hunt.draft.model_dump_json(indent=1)),
            "",
            "Deterministic lint findings:",
            *lint_lines,
        ]
    )


def second_review_hunt(
    hunt: Hunt,
    evidence: list[str],
    *,
    client: LLMClient,
    tracer: Tracer,
    settings: Settings,
    system: str,
    actor: str | None = None,
    surroundings: str | None = None,
    facts: str | None = None,
) -> Hunt:
    """A second, independent review on a different model, merged into the attention list
    by code. It can add reasons to look at a hunt; it can't remove the first reviewer's."""
    result = traced_call(
        client=client, tracer=tracer, stage="reviewer2", step=hunt.draft_id,
        model=settings.review2_model, system=system,
        user=review_user(hunt, evidence, actor, surroundings, facts),
        schema=ReviewScores, max_tokens=settings.analyse_max_output_tokens,
        effort=settings.review2_effort, refusal_fallback=True,
    )  # fmt: skip
    outcome = "skipped_budget" if result is None else outcome_of(result)
    second = result.parsed if result is not None else None
    answered_by = result.model if result is not None else None
    added = second_opinion_reasons(hunt.review, second, outcome, answered_by, settings.review_model)
    reasons = hunt.attention_reasons + [r for r in added if r not in hunt.attention_reasons]
    return hunt.model_copy(
        update={
            "second_review": second,
            "second_review_model": answered_by,
            "second_review_outcome": outcome,
            "needs_attention": bool(reasons),
            "attention_reasons": reasons,
        }
    )


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
    facts: str | None = None,
) -> Hunt:
    """`facts` are pipeline facts from structured fields that the analyst was also given,
    so the reviewer doesn't mistake them for invention."""
    user = review_user(hunt, evidence, actor, surroundings, facts)
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
