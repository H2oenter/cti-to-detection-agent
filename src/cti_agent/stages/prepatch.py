"""Pre-patch hunts for one triaged advisory: an exposure query and a behaviour hunt.

The exposure query is written by code: the facts it needs (product, affected and fixed
versions) are structured fields in the feed, so a model adds nothing but risk. The
behaviour hunt needs judgement, so the analyst model drafts it from observables pulled
out of the advisory text, each verified against that text, and the reviewer scores it.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from cti_agent.attack.attack_index import AttackLookup
from cti_agent.feeds.triage import WatchedProduct
from cti_agent.models import (
    Confidence,
    CoverageEntry,
    Hunt,
    HuntDraft,
    Observable,
    PrepatchExtraction,
    VulnAdvisory,
)
from cti_agent.stages.validator import verify_quote
from cti_agent.util.kql_lint import KqlSchema, lint_kql
from cti_agent.util.normalise import SourceIndex, item_hash

_NUMERIC = re.compile(r"^\d+(?:\.\d+){0,3}$")
DEFAULT_TECHNIQUE = "T1190"  # Exploit Public-Facing Application
RETIRE_AFTER = timedelta(days=30)


def advisory_text(advisory: VulnAdvisory) -> str:
    return f"{advisory.title or advisory.id}\n\n{advisory.description}".strip()


def first_sentence(text: str) -> str:
    match = re.match(r"(.+?[.!?])(\s|$)", " ".join(text.split()))
    return match.group(1) if match else " ".join(text.split())[:200]


def fixed_versions(advisory: VulnAdvisory) -> list[str]:
    return sorted({r.fixed for p in advisory.affected for r in p.ranges if r.fixed})


def verify_observables(
    extraction: PrepatchExtraction, source: SourceIndex
) -> tuple[list[Observable], list[str]]:
    kept, rejected = [], []
    for obs in extraction.observables:
        reason = verify_quote(source, obs.evidence.quote)
        if reason:
            rejected.append(f"{reason}: {obs.description}")
        else:
            kept.append(obs)
    return kept, rejected


def choose_technique(
    extraction: PrepatchExtraction | None, source: SourceIndex, attack: AttackLookup
) -> CoverageEntry:
    """The first verified initial-access or execution technique the text names, else T1190."""
    candidates = []
    if extraction:
        for tech in extraction.techniques:
            info = attack.lookup(tech.attack_id)
            if info and not verify_quote(source, tech.evidence.quote):
                candidates.append(info)
    preferred = [i for i in candidates if {"initial-access", "execution"} & set(i.tactics)]
    info = (preferred or candidates or [attack.lookup(DEFAULT_TECHNIQUE)])[0]
    return CoverageEntry(
        attack_id=info.attack_id,
        name=info.name,
        domain=info.domain,
        tactics=list(info.tactics),
        state="gap",
        evidence_kind="explicit",
    )


def retire_when(advisory: VulnAdvisory, product: str, now: datetime) -> str:
    fixed = fixed_versions(advisory)
    patched = (
        f"{product} is at {', '.join(fixed)} or later everywhere (the exposure query returns "
        "nothing)"
        if fixed
        else f"a fixed {product} release is deployed everywhere"
    )
    return f"Retire when {patched}, or on {(now + RETIRE_AFTER):%Y-%m-%d}, whichever is first."


def _kql_list(values: tuple[str, ...] | list[str]) -> str:
    return ", ".join('"' + v.replace('"', "") + '"' for v in values)


def exposure_query(advisory: VulnAdvisory, watched: WatchedProduct) -> tuple[str, list[str]]:
    """Returns (query, assumptions). Inventory only: it says nothing about exploitation."""
    assumptions = [
        f"Defender TVM lists the software with SoftwareName matching {list(watched.tvm_names)}; "
        "check the exact name in your tenant.",
    ]
    conditions = []
    for product in advisory.affected:
        for r in product.ranges:
            if r.fixed and _NUMERIC.match(r.fixed):
                lower = (
                    f'Version >= parse_version("{r.introduced}") and '
                    if r.introduced and _NUMERIC.match(r.introduced)
                    else ""
                )
                conditions.append(f'({lower}Version < parse_version("{r.fixed}"))')
    if any(p.ecosystem for p in advisory.affected):
        assumptions.append(
            "Defender doesn't inventory npm or Composer dependencies: this finds hosts running "
            f"{watched.name}; check SBOMs or lock files for the affected package itself."
        )
    by_version = (
        "DeviceTvmSoftwareInventory\n"
        f"    | where SoftwareName has_any ({_kql_list(watched.tvm_names)})\n"
        "    | extend Version = parse_version(SoftwareVersion)\n"
        + (f"    | where {' or '.join(sorted(set(conditions)))}\n" if conditions else "")
        + '    | project DeviceName, SoftwareName, SoftwareVersion, Basis = "version range"'
    )
    if not conditions:
        assumptions.append("The advisory gives no numeric version range: every install is listed.")
    query = (
        f"// Which devices run a {watched.name} version affected by {advisory.id}?\n"
        "// Inventory, not exploitation. Snapshot tables, so there is no time filter.\n"
        f"let byVersion = {by_version};\n"
        "let byCve = DeviceTvmSoftwareVulnerabilities\n"
        f'    | where CveId == "{advisory.id}"\n'
        "    | project DeviceName, SoftwareName, SoftwareVersion,"
        ' Basis = "Defender TVM CVE match";\n'
        "union byVersion, byCve\n"
        "| summarize Basis = make_set(Basis) by DeviceName, SoftwareName, SoftwareVersion\n"
        "| order by DeviceName asc"
    )
    return query, assumptions


def exposure_hunt(
    advisory: VulnAdvisory,
    watched: WatchedProduct,
    technique: str,
    schema: KqlSchema,
    retire: str,
) -> Hunt:
    query, assumptions = exposure_query(advisory, watched)
    draft = HuntDraft(
        title=f"Exposure: {watched.name} versions affected by {advisory.id}",
        technique_id=technique,
        tables=["DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities"],
        query=query,
        evidence_quotes=[first_sentence(advisory.description or advisory_text(advisory))],
        expected_false_positives=[
            "Backported or vendor-patched builds that keep an old version string",
        ],
        tuning_notes="Scope to internet-facing hosts first; they are the ones T1190 reaches.",
        assumptions=assumptions,
        confidence=Confidence(
            score=90, rationale="Inventory match on structured version data, not exploitation."
        ),
    )
    lint = [f for f in lint_kql(query, draft.tables, schema) if f.code != "no_time_filter"]
    return Hunt(
        draft_id=f"{advisory.id}-exposure",
        kind="exposure",
        technique_id=technique,
        draft=draft,
        lint=lint,
        review_outcome="not reviewed: written by code from structured advisory fields",
        needs_attention=any(f.severity == "error" for f in lint),
        attention_reasons=[f"lint {f.code}" for f in lint if f.severity == "error"],
        item_hash=item_hash(draft),
        model="code",
        prompt_version="exposure@v1",
        retire_when=retire,
    )


def behaviour_surroundings(advisory: VulnAdvisory, extraction: PrepatchExtraction | None) -> str:
    """The advisory text plus the model's summary of it. Both derive from untrusted text, so
    the caller passes this as wrapped context, never as instructions."""
    text = advisory_text(advisory)
    if extraction:
        text += (
            f"\n\nModel-extracted summary (unverified): vector '{extraction.attack_vector}'; "
            f"component '{extraction.vulnerable_component}'; preconditions "
            f"{extraction.preconditions or 'none stated'}."
        )
    return text


def behaviour_context(advisory: VulnAdvisory, watched: WatchedProduct, signals: list[str]) -> str:
    """Facts from structured fields and the watchlist. Free text goes in the wrapped context."""
    affected = "; ".join(
        f"{p.vendor or p.ecosystem or ''} {p.product}"
        + (f" on {', '.join(p.platforms)}" if p.platforms else "")
        + (f" ({', '.join(p.modules)})" if p.modules else "")
        for p in advisory.affected
    )
    lines = [
        f"This is a pre-patch hunt for {advisory.id}. Hunt for exploitation of this flaw in "
        f"{watched.name}, not for the technique in general.",
        f"Affected: {affected or 'see the advisory'}. Fixed in: "
        f"{', '.join(fixed_versions(advisory)) or 'no fixed version listed'}.",
        f"{watched.name} runs as: {', '.join(watched.processes)}. "
        f"Commonly behind: {', '.join(watched.servers)}.",
        f"Exploitation signals: {'; '.join(signals) or 'none known'}.",
    ]
    return "\n".join(lines)
