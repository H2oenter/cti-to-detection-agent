"""JSONL traces and the per-run token budget.

One line per step. Traces hold counts, timings and outcomes, never prompts,
report text or credentials (design rule 7).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.config import Settings


def estimate_tokens(text: str) -> int:
    """Rough upper estimate for budget checks; actual usage comes back from the API."""
    return len(text) * 2 // 7 + 1  # about 3.5 characters per token


class Tracer:
    def __init__(self, run_id: str, path: Path, settings: Settings) -> None:
        self.run_id = run_id
        self.path = path
        self.settings = settings
        self.budget = settings.max_tokens_per_run
        self.input_tokens = 0
        self.output_tokens = 0
        self.cost_usd = 0.0

    @property
    def used(self) -> int:
        return self.input_tokens + self.output_tokens

    def can_spend(self, tokens: int) -> bool:
        return self.used + tokens <= self.budget

    def record(
        self,
        *,
        stage: str,
        step: str,
        outcome: str,
        model: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
        detail: str | None = None,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        cost = (
            self.settings.estimate_cost(
                model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens
            )
            if model
            else 0.0
        ) or 0.0
        # Cached tokens are still processed, so they count against the budget.
        self.input_tokens += input_tokens + cache_read_tokens + cache_write_tokens
        self.output_tokens += output_tokens
        self.cost_usd += cost
        line = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "run_id": self.run_id,
            "stage": stage,
            "step": step,
            "model": model,
            "input_tokens": input_tokens + cache_read_tokens + cache_write_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cache_write_tokens": cache_write_tokens,
            "output_tokens": output_tokens,
            "latency_ms": latency_ms,
            "est_cost_usd": round(cost, 6),
            "outcome": outcome,
            "detail": detail,
            "budget_used": self.used,
            "budget": self.budget,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")


def read_trace(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
