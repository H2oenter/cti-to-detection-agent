"""One .kql file per hunt, with its provenance in a comment header."""

from __future__ import annotations

from pathlib import Path

from cti_agent.models import Hunt


def _one_line(text: str) -> str:
    return " ".join(text.split())


def render_kql(hunt: Hunt) -> str:
    d = hunt.draft
    header = [
        "// DRAFT HUNT: not approved by a human. Do not deploy before review.",
        f"// {_one_line(d.title)}",
        f"// Technique: {hunt.technique_id}   Kind: {hunt.kind}",
        f"// Tables: {', '.join(d.tables)}",
        f"// Confidence: {d.confidence.score}/100. {_one_line(d.confidence.rationale)}",
        "// Evidence:",
        *[f'//   "{_one_line(q)}"' for q in d.evidence_quotes],
        "// Expected false positives:",
        *[f"//   - {_one_line(fp)}" for fp in d.expected_false_positives],
    ]
    if hunt.review:
        r = hunt.review
        header.append(
            f"// Reviewer: faithful {r.faithful}, kql_correct {r.kql_correct}, "
            f"actionable {r.actionable}, calibrated {r.calibrated}"
        )
    else:
        header.append(f"// Reviewer: none ({hunt.review_outcome})")
    header += [f"// Lint {f.severity}: {f.code}: {_one_line(f.message)}" for f in hunt.lint]
    if hunt.needs_attention:
        header.append(f"// NEEDS ATTENTION: {'; '.join(hunt.attention_reasons)}")
    if hunt.retire_when:
        header.append(f"// Retire when: {hunt.retire_when}")
    header.append(f"// Model: {hunt.model} ({hunt.prompt_version})   Item: {hunt.item_hash}")
    return "\n".join([*header, "", d.query.strip(), ""])


def write_hunts(hunts: list[Hunt], directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for hunt in hunts:
        path = directory / f"{hunt.draft_id}.kql"
        path.write_text(render_kql(hunt), encoding="utf-8")
        paths.append(path)
    return paths
