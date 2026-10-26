"""Stage 1: one structured-output call per chunk. The model gets no tools.

Report text is wrapped in <untrusted_report> tags (design rule 1). Results are
kept per chunk, raw, so the eval can see what the model said before the
validator filtered it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from cti_agent.config import Settings
from cti_agent.llm.client import FatalLLMError, LLMClient
from cti_agent.llm.prompting import Prompt
from cti_agent.models import Extraction
from cti_agent.trace import Tracer, estimate_tokens

CHARS_PER_TOKEN = 4.0
_TAG = re.compile(r"<\s*/?\s*untrusted_report\b[^>]*>", re.IGNORECASE)

ChunkOutcome = Literal["ok", "refused", "truncated", "invalid_output", "error", "skipped_budget"]


@dataclass
class Chunk:
    index: int  # 1-based
    text: str


@dataclass
class ChunkResult:
    index: int
    outcome: ChunkOutcome
    extraction: Extraction | None
    detail: str | None = None


def chunk_text(text: str, target_tokens: int, overlap_ratio: float) -> list[Chunk]:
    """Split on paragraph boundaries into chunks of about `target_tokens`, with overlap."""
    target = int(target_tokens * CHARS_PER_TOKEN)
    overlap = int(target * overlap_ratio)
    pieces: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        while len(para) > target:
            cut = para.rfind("\n", 0, target)
            if cut < target // 2:
                cut = para.rfind(" ", 0, target)
            if cut <= 0:
                cut = target
            pieces.append(para[:cut].strip())
            para = para[cut:].strip()
        if para:
            pieces.append(para)

    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for piece in pieces:
        if current and size + len(piece) > target:
            chunks.append("\n\n".join(current))
            tail: list[str] = []
            tail_size = 0
            for prev in reversed(current):
                if tail_size + len(prev) > overlap:
                    break
                tail.insert(0, prev)
                tail_size += len(prev) + 2
            current, size = tail, tail_size
        current.append(piece)
        size += len(piece) + 2
    if current:
        chunks.append("\n\n".join(current))
    return [Chunk(index=i, text=t) for i, t in enumerate(chunks, start=1)]


def wrap_untrusted(text: str) -> str:
    """Wrap report text in tags, neutralising any tag the report itself contains."""
    safe = _TAG.sub(lambda m: m.group(0).replace("<", "&lt;").replace(">", "&gt;"), text)
    return f"<untrusted_report>\n{safe}\n</untrusted_report>"


def collect(
    text: str, *, client: LLMClient, tracer: Tracer, settings: Settings, prompt: Prompt
) -> list[ChunkResult]:
    chunks = chunk_text(text, settings.chunk_target_tokens, settings.chunk_overlap_ratio)
    results: list[ChunkResult] = []
    for chunk in chunks:
        step = f"chunk {chunk.index}/{len(chunks)}"
        user = f"Chunk {chunk.index} of {len(chunks)}.\n\n{wrap_untrusted(chunk.text)}"
        needed = estimate_tokens(prompt.text + user) + settings.extract_max_output_tokens
        if not tracer.can_spend(needed):
            detail = f"needs ~{needed} tokens, {tracer.budget - tracer.used} left"
            for rest in chunks[chunk.index - 1 :]:
                results.append(ChunkResult(rest.index, "skipped_budget", None, detail))
                tracer.record(
                    stage="collector",
                    step=f"chunk {rest.index}/{len(chunks)}",
                    outcome="skipped_budget",
                    detail=detail,
                )
            break

        try:
            result = client.structured(
                model=settings.extract_model,
                system=prompt.text,
                user=user,
                schema=Extraction,
                max_tokens=settings.extract_max_output_tokens,
                effort=settings.extract_effort,
            )
        except FatalLLMError as exc:
            tracer.record(
                stage="collector", step=step, outcome="fatal_error", detail=str(exc)[:300]
            )
            raise
        outcome = _outcome(result.stop_reason, result.parsed is not None)
        tracer.record(
            stage="collector",
            step=step,
            outcome=outcome,
            model=result.model,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            latency_ms=result.latency_ms,
            detail=result.detail,
        )
        results.append(ChunkResult(chunk.index, outcome, result.parsed, result.detail))
    return results


def _outcome(stop_reason: str, parsed: bool) -> ChunkOutcome:
    if parsed:
        return "ok"
    return {
        "refusal": "refused",
        "max_tokens": "truncated",
        "invalid_output": "invalid_output",
    }.get(stop_reason, "error")
