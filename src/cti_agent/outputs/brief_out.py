"""The markdown brief: three sentences for leadership, then detail for detection engineers.

Only the leadership sentences come from a model, and it sees computed facts, never
report text. Code checks that every number and technique ID it uses is in those
facts; if not, a template is used instead. Everything else is rendered from data.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from pydantic import BaseModel, Field

from cti_agent.config import Settings
from cti_agent.llm.client import LLMClient
from cti_agent.llm.steps import traced_call
from cti_agent.models import AnalysisResult, PrepatchResult, Provenance
from cti_agent.trace import Tracer

MAX_WORDS_PER_SENTENCE = 60


class LeadershipSummary(BaseModel):
    sentences: list[str] = Field(description="Exactly three plain sentences for a leader.")


def brief_facts(analysis: AnalysisResult, title: str, indicator_count: int) -> dict:
    states = Counter(e.state for e in analysis.coverage)
    names = {e.attack_id: e.name for e in analysis.coverage}
    return {
        "report_title": title,
        "actor": analysis.actor,
        "techniques_total": len(analysis.coverage),
        "tactics_total": len(analysis.tactics),
        "covered": states["covered"],
        "partially_covered": states["partial"],
        "gaps": states["gap"],
        "mobile_not_huntable": states["not_applicable"],
        "indicators_accepted": indicator_count,
        "hunts_drafted": len(analysis.hunts),
        "hunts_needing_attention": sum(h.needs_attention for h in analysis.hunts),
        # The gaps the draft hunts target, in the order they were chosen.
        "draft_hunts_target": [
            {"id": h.technique_id, "name": names.get(h.technique_id, h.technique_id)}
            for h in analysis.hunts
        ],
    }


def check_summary(sentences: list[str], facts: dict) -> list[str]:
    problems = []
    if not 1 <= len(sentences) <= 3:
        problems.append(f"{len(sentences)} sentences, expected 3")
    text = " ".join(sentences)
    facts_text = json.dumps(facts)
    allowed_numbers = set(re.findall(r"\d+", facts_text))
    invented = sorted(set(re.findall(r"\d+", text)) - allowed_numbers)
    if invented:
        problems.append("numbers not in the facts: " + ", ".join(invented))
    ids = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))
    unknown_ids = sorted(i for i in ids if i not in facts_text)
    if unknown_ids:
        problems.append("technique IDs not in the facts: " + ", ".join(unknown_ids))
    if any(len(s.split()) > MAX_WORDS_PER_SENTENCE for s in sentences):
        problems.append("a sentence is too long")
    return problems


def template_summary(facts: dict) -> str:
    actor = facts["actor"] or "The actor in this report"
    targets = ", ".join(t["name"] for t in facts["draft_hunts_target"]) or "none"
    return (
        f"{actor} activity in this report maps to {facts['techniques_total']} ATT&CK techniques "
        f"across {facts['tactics_total']} tactics. "
        f"The current rule set covers {facts['covered']} fully and "
        f"{facts['partially_covered']} partly, leaving {facts['gaps']} gaps. "
        f"{facts['hunts_drafted']} draft hunts ({targets}) are waiting for analyst review, "
        f"{facts['hunts_needing_attention']} of them flagged for attention, and nothing is "
        "deployed until an analyst approves it."
    )


def leadership_summary(
    facts: dict, *, client: LLMClient, tracer: Tracer, settings: Settings, system: str
) -> tuple[str, str]:
    """Returns (text, source), where source is "model" or "template"."""
    result = traced_call(
        client=client,
        tracer=tracer,
        stage="brief",
        step="leadership",
        model=settings.analyse_model,
        system=system,
        user=f"<facts>\n{json.dumps(facts, indent=1)}\n</facts>",
        schema=LeadershipSummary,
        max_tokens=2_000,
        effort="low",
        refusal_fallback=True,
    )
    if result is not None and result.parsed is not None:
        sentences = [s.strip() for s in result.parsed.sentences if s.strip()]
        problems = check_summary(sentences, facts)
        if not problems:
            return " ".join(sentences), "model"
        tracer.record(
            stage="brief", step="fact-check", outcome="rejected", detail="; ".join(problems)
        )
    return template_summary(facts), "template"


def render_brief(
    analysis: AnalysisResult, facts: dict, provenance: Provenance, attack_description: str
) -> str:
    title = facts["report_title"]
    out = [
        f"# Threat brief: {title}",
        "",
        f"Run `{analysis.run_id}` · source `{provenance.source_file}` "
        f"(sha256 `{provenance.source_sha256[:12]}…`) · TLP:{provenance.tlp} · "
        f"**DRAFT, pending human review**",
        "",
        "## For leadership",
        "",
        analysis.leadership_summary,
        "",
        "## For detection engineers",
        "",
        "### Techniques by tactic",
        "",
        "| Tactic | Techniques |",
        "| --- | --- |",
        *[f"| {t} | {', '.join(ids)} |" for t, ids in analysis.tactics.items()],
        "",
        "### Coverage against the rule set (sample rules are fictional)",
        "",
        "| Technique | Name | Coverage | Rules or note |",
        "| --- | --- | --- | --- |",
    ]
    for e in analysis.coverage:
        detail = "; ".join(filter(None, [", ".join(e.rules), e.note])) or ""
        out.append(f"| {e.attack_id} | {e.name} | {e.state} | {detail} |")
    out += ["", "### Draft hunts", ""]
    if not analysis.hunts:
        out.append("No hunts were drafted.")
    for h in analysis.hunts:
        d = h.draft
        scores = (
            " · ".join(f"{k} {getattr(h.review, k)}" for k in
                       ("faithful", "kql_correct", "actionable", "calibrated"))
            if h.review else f"no review ({h.review_outcome})"
        )  # fmt: skip
        lint = "; ".join(f"{f.severity} {f.code}" for f in h.lint) or "clean"
        flag = f" ⚠ needs attention: {'; '.join(h.attention_reasons)}" if h.needs_attention else ""
        out += [
            f"#### {h.technique_id}: {d.title}",
            "",
            f"- Tables: {', '.join(d.tables)}",
            *[f'- Evidence: "{q}"' for q in d.evidence_quotes],
            f"- Confidence: {d.confidence.score}/100. {d.confidence.rationale}",
            f"- Expected false positives: {'; '.join(d.expected_false_positives)}",
            f"- Reviewer: {scores}{flag}",
            f"- Lint: {lint}",
            *([f"- Retire when: {h.retire_when}"] if h.retire_when else []),
            "",
            "```kql",
            d.query.strip(),
            "```",
            "",
        ]
    if analysis.not_drafted:
        out += ["### Gaps not drafted this run", "", ", ".join(analysis.not_drafted), ""]
    models = sorted({h.model for h in analysis.hunts})
    out += [
        "### Provenance",
        "",
        f"- Extraction: {provenance.model} ({provenance.prompt_version})",
        f"- Analysis and review: {', '.join(models) or 'none'}",
        f"- ATT&CK: {attack_description}",
        f"- Leadership summary: {analysis.summary_source}",
        "",
    ]
    return "\n".join(out)


def render_prepatch_brief(result: PrepatchResult, provenance: Provenance) -> str:
    adv = result.advisory
    fixed = sorted({r.fixed for p in adv.affected for r in p.ranges if r.fixed})
    affected = "; ".join(
        f"{p.vendor or p.ecosystem or ''} {p.product}".strip()
        + (f" ({', '.join(p.platforms)})" if p.platforms else "")
        for p in adv.affected
    )
    out = [
        f"# Pre-patch brief: {adv.id}",
        "",
        f"{adv.title or ''}",
        "",
        f"Run `{result.run_id}` · from {provenance.source_name} · **DRAFT, pending human review**",
        "",
        "| | |",
        "| --- | --- |",
        f"| Product (watchlist) | {result.product or 'not on the watchlist'} |",
        f"| Affected | {affected or 'not stated'} |",
        f"| Fixed in | {', '.join(fixed) or 'no fixed version listed'} |",
        f"| CVSS | {adv.cvss_score or 'n/a'} |",
        f"| CISA KEV | {'yes, due ' + str(adv.kev_due_date) if adv.kev_listed else 'no'} |",
        f"| SSVC exploitation | {adv.ssvc_exploitation or 'n/a'} |",
        f"| Why it passed triage | {'; '.join(result.signals) or 'n/a'} |",
        "",
        f"**{result.retire_when}**",
        "",
        "## Advisory text (as published)",
        "",
        f"> {' '.join(adv.description.split())}",
        "",
    ]
    if result.observables or result.rejected_observables:
        out += ["## Observables pulled from the text", ""]
        out += [f'- {o.description}: "{o.evidence.quote}"' for o in result.observables]
        out += [f"- rejected ({r})" for r in result.rejected_observables]
        out.append("")
    out += ["## Hunts", ""]
    for h in result.hunts:
        d = h.draft
        review = (
            " · ".join(f"{k} {getattr(h.review, k)}" for k in
                       ("faithful", "kql_correct", "actionable", "calibrated"))
            if h.review else h.review_outcome
        )  # fmt: skip
        flag = f" ⚠ needs attention: {'; '.join(h.attention_reasons)}" if h.needs_attention else ""
        out += [
            f"### {d.title}",
            "",
            f"- Kind: {h.kind} · technique {h.technique_id} · by {h.model}",
            f"- Confidence: {d.confidence.score}/100. {d.confidence.rationale}",
            f"- Review: {review}{flag}",
            f"- Lint: {'; '.join(f'{f.severity} {f.code}' for f in h.lint) or 'clean'}",
            *[f"- Assumption: {a}" for a in d.assumptions],
            "",
            "```kql",
            d.query.strip(),
            "```",
            "",
        ]
    out += [
        "### Provenance",
        "",
        f"- Records: {provenance.fetched_from}",
        f"- Extraction: {provenance.model} ({provenance.prompt_version})",
        "",
    ]
    return "\n".join(out)
