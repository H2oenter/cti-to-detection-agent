"""One budgeted, traced model call. Every LLM stage after the collector goes through here."""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from cti_agent.llm.client import FatalLLMError, LLMClient, LLMResult
from cti_agent.trace import Tracer, estimate_tokens

T = TypeVar("T", bound=BaseModel)


def outcome_of(result: LLMResult) -> str:
    if result.parsed is not None:
        return "ok"
    return {
        "refusal": "refused",
        "max_tokens": "truncated",
        "invalid_output": "invalid_output",
    }.get(result.stop_reason, "error")


def traced_call(
    *,
    client: LLMClient,
    tracer: Tracer,
    stage: str,
    step: str,
    model: str,
    system: str,
    user: str,
    schema: type[T],
    max_tokens: int,
    effort: str | None = None,
    refusal_fallback: bool = False,
) -> LLMResult[T] | None:
    """Check the budget, call the model, write the trace line. None means skipped for budget."""
    needed = estimate_tokens(system + user) + max_tokens
    if not tracer.can_spend(needed):
        tracer.record(
            stage=stage,
            step=step,
            outcome="skipped_budget",
            detail=f"needs ~{needed} tokens, {tracer.budget - tracer.used} left",
        )
        return None
    try:
        result = client.structured(
            model=model,
            system=system,
            user=user,
            schema=schema,
            max_tokens=max_tokens,
            effort=effort,
            refusal_fallback=refusal_fallback,
        )
    except FatalLLMError as exc:
        tracer.record(stage=stage, step=step, outcome="fatal_error", detail=str(exc)[:300])
        raise
    tracer.record(
        stage=stage,
        step=step,
        outcome=outcome_of(result),
        model=result.model,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        cache_read_tokens=result.cache_read_tokens,
        cache_write_tokens=result.cache_write_tokens,
        latency_ms=result.latency_ms,
        detail=result.detail,
    )
    return result
