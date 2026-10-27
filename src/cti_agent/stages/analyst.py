"""Stage 4b: draft one KQL hunt per selected gap. The model has no tools; code checks its work.

The analyst sees evidence quotes, which are report text, so they're wrapped as untrusted.
Its draft must cite that evidence verbatim (design rule 4, extended to hunts), and the
query goes through the deterministic lint before any reviewer or human sees it.
"""

from __future__ import annotations

import json
from pathlib import Path

from cti_agent.config import Settings
from cti_agent.llm.client import LLMClient
from cti_agent.llm.steps import outcome_of, traced_call
from cti_agent.models import CoverageEntry, Hunt, HuntDraft, LintFinding
from cti_agent.stages.collector import wrap_untrusted
from cti_agent.trace import Tracer
from cti_agent.util.kql_lint import KqlSchema, lint_kql
from cti_agent.util.normalise import item_hash, match_key


def schema_text(schema_file: Path) -> str:
    """The table list given to the analyst and reviewer, one line per table."""
    tables = json.loads(schema_file.read_text(encoding="utf-8"))["tables"]
    return "\n".join(
        f"- {name} ({t['product']}): {', '.join(t['columns'])}" for name, t in tables.items()
    )


def evidence_block(evidence: list[str], surroundings: str | None) -> list[str]:
    """The evidence as the analyst and reviewer see it: quotes to cite, then context."""
    lines = [
        "",
        "Evidence from the report (cite these quotes exactly):",
        wrap_untrusted("\n".join(f"- {q}" for q in evidence)),
    ]
    if surroundings:
        lines += [
            "",
            "The report text around that evidence, for context only:",
            wrap_untrusted(surroundings),
        ]
    return lines


def check_evidence(quotes: list[str], given: list[str]) -> list[LintFinding]:
    if not quotes:
        return [LintFinding(severity="error", code="no_evidence", message="cites no evidence")]
    given_keys = [match_key(g) for g in given]
    return [
        LintFinding(
            severity="error",
            code="evidence_not_given",
            message=f"quote is not from the evidence given: {q[:80]!r}",
        )
        for q in quotes
        if not (key := match_key(q)) or not any(key in g for g in given_keys)
    ]


def draft_hunt(
    entry: CoverageEntry,
    evidence: list[str],
    actor: str | None,
    *,
    client: LLMClient,
    tracer: Tracer,
    settings: Settings,
    system: str,
    prompt_version: str,
    schema: KqlSchema,
    kind: str = "coverage_gap",
    surroundings: str | None = None,
    extra: str | None = None,
) -> tuple[Hunt | None, str]:
    """Returns (hunt, outcome). The hunt is None when nothing usable came back."""
    lines = [
        f"Technique: {entry.attack_id} {entry.name}",
        f"Tactics: {', '.join(entry.tactics) or 'none listed'}",
        f"Threat actor: {actor or 'not named in the report'}",
        "Coverage: no rule in the current rule set covers this technique.",
    ]
    if extra:
        lines.append(extra)
    lines += evidence_block(evidence, surroundings)
    result = traced_call(
        client=client,
        tracer=tracer,
        stage="analyst",
        step=entry.attack_id,
        model=settings.analyse_model,
        system=system,
        user="\n".join(lines),
        schema=HuntDraft,
        max_tokens=settings.analyse_max_output_tokens,
        effort=settings.analyse_effort,
        refusal_fallback=True,
    )
    if result is None:
        return None, "skipped_budget"
    if result.parsed is None:
        return None, outcome_of(result)

    draft: HuntDraft = result.parsed
    findings = lint_kql(draft.query, draft.tables, schema) + check_evidence(
        draft.evidence_quotes, evidence
    )
    if draft.technique_id.strip().upper() != entry.attack_id:
        findings.append(
            LintFinding(
                severity="warning",
                code="technique_mismatch",
                message=f"draft says {draft.technique_id}, it was asked for {entry.attack_id}",
            )
        )
    hunt = Hunt(
        draft_id=f"{entry.attack_id}-{kind.replace('_', '-')}",
        kind=kind,
        technique_id=entry.attack_id,
        draft=draft,
        lint=findings,
        item_hash=item_hash(draft),
        model=result.model,
        prompt_version=prompt_version,
    )
    return hunt, "ok"
