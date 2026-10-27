"""STIX 2.1 bundle for one run. Provenance and evidence ride along in x_cti_agent_* properties."""

from __future__ import annotations

import uuid
from datetime import timedelta

import stix2

from cti_agent.attack.attack_index import AttackLookup
from cti_agent.models import (
    AcceptedItem,
    ExtractedActor,
    ExtractedCVE,
    ExtractedIndicator,
    ExtractedTechnique,
    Provenance,
    ValidationResult,
)

INDICATOR_VALIDITY = timedelta(days=90)
_NAMESPACE = uuid.UUID("0d5a3c6e-9a43-4f0e-8a3c-5b8f6f2b7c11")

TOOL_IDENTITY = stix2.Identity(
    id=f"identity--{uuid.uuid5(_NAMESPACE, 'cti-to-detection-agent')}",
    name="cti-to-detection-agent",
    identity_class="system",
    description="Automated extraction. Every object carries the quote it was checked against.",
    created="2026-10-26T00:00:00.000Z",
    modified="2026-10-26T00:00:00.000Z",
)

# The stix2 library ships TLP 1.0 markings. The exact TLP 2.0 label is kept in x_cti_agent_tlp.
TLP_MARKINGS = {
    "CLEAR": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "AMBER+STRICT": stix2.TLP_AMBER,
    "RED": stix2.TLP_RED,
}

_PATTERNS = {
    "ipv4": "[ipv4-addr:value = '{}']",
    "ipv6": "[ipv6-addr:value = '{}']",
    "domain": "[domain-name:value = '{}']",
    "url": "[url:value = '{}']",
    "email": "[email-addr:value = '{}']",
    "sha256": "[file:hashes.'SHA-256' = '{}']",
    "sha1": "[file:hashes.'SHA-1' = '{}']",
    "md5": "[file:hashes.MD5 = '{}']",
}


def stix_pattern(kind: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return _PATTERNS[kind].format(escaped)


def build_bundle(
    validation: ValidationResult, provenance: Provenance, report_title: str, attack: AttackLookup
) -> stix2.Bundle:
    b = _Builder(provenance)
    actors, indicators, patterns, vulns = [], [], [], []
    for acc in validation.accepted:
        item = acc.item
        if isinstance(item, ExtractedIndicator):
            indicators.append(b.indicator(acc, item))
        elif isinstance(item, ExtractedTechnique):
            patterns.append(b.attack_pattern(acc, item, attack))
        elif isinstance(item, ExtractedActor):
            actors.append(b.threat_actor(acc, item))
        elif isinstance(item, ExtractedCVE):
            vulns.append(b.vulnerability(acc, item))

    # Relationships are only drawn when the report names exactly one actor; with several,
    # the pipeline can't tell who did what, so it doesn't guess.
    relationships = []
    if len(actors) == 1:
        [actor] = actors
        relationships += [b.relationship(i, "indicates", actor) for i in indicators]
        relationships += [b.relationship(actor, "uses", p) for p in patterns]
        relationships += [b.relationship(actor, "targets", v) for v in vulns]

    content = [*actors, *indicators, *patterns, *vulns, *relationships]
    report = b.report(report_title, content)
    bundle = stix2.Bundle(
        objects=[TLP_MARKINGS[provenance.tlp], TOOL_IDENTITY, report, *content], allow_custom=True
    )
    stix2.parse(bundle.serialize(), allow_custom=True)  # round-trip: fail loudly if invalid
    return bundle


class _Builder:
    def __init__(self, provenance: Provenance) -> None:
        self.p = provenance

    def _id(self, stix_type: str, key: str) -> str:
        return f"{stix_type}--{uuid.uuid5(_NAMESPACE, f'{self.p.run_id}|{stix_type}|{key}')}"

    def _common(self, acc: AcceptedItem | None = None) -> dict:
        p = self.p
        props = {
            "created_by_ref": TOOL_IDENTITY.id,
            "created": p.ingested_at,
            "modified": p.ingested_at,
            "object_marking_refs": [TLP_MARKINGS[p.tlp].id],
            "allow_custom": True,
            "x_cti_agent_run_id": p.run_id,
            "x_cti_agent_source_file": p.source_file,
            "x_cti_agent_source_sha256": p.source_sha256,
            "x_cti_agent_source_kind": p.source_kind,
            "x_cti_agent_tlp": p.tlp,
            "x_cti_agent_model": p.model,
            "x_cti_agent_prompt_version": p.prompt_version,
        }
        if acc is not None:
            props["x_cti_agent_item_hash"] = acc.item_hash
            props["x_cti_agent_evidence_quote"] = acc.item.evidence.quote
            props["x_cti_agent_evidence_kind"] = acc.evidence_kind
            if acc.page is not None:
                props["x_cti_agent_evidence_page"] = acc.page
            if acc.warnings:
                props["x_cti_agent_warnings"] = acc.warnings
            if acc.recheck_role:  # a fixed label; the re-check's own words stay in recheck.json
                props["x_cti_agent_recheck_role"] = acc.recheck_role
        return props

    def indicator(self, acc: AcceptedItem, item: ExtractedIndicator) -> stix2.Indicator:
        return stix2.Indicator(
            id=self._id("indicator", f"{item.kind}:{item.value}"),
            name=item.value,
            description=item.context,
            indicator_types=["malicious-activity"],
            pattern=stix_pattern(item.kind, item.value),
            pattern_type="stix",
            valid_from=self.p.ingested_at,
            valid_until=self.p.ingested_at + INDICATOR_VALIDITY,
            **self._common(acc),
        )

    def attack_pattern(
        self, acc: AcceptedItem, item: ExtractedTechnique, attack: AttackLookup
    ) -> stix2.AttackPattern:
        info = attack.lookup(item.attack_id)
        ref = {"source_name": "mitre-attack", "external_id": item.attack_id}
        if info and info.url:
            ref["url"] = info.url
        extra = {}
        if info and info.tactics:
            extra["kill_chain_phases"] = [
                {"kill_chain_name": info.kill_chain, "phase_name": t} for t in info.tactics
            ]
        if info:
            extra["x_cti_agent_attack_domain"] = info.domain
        return stix2.AttackPattern(
            id=self._id("attack-pattern", item.attack_id),
            name=info.name if info else item.attack_id,
            description=item.behaviour,
            external_references=[ref],
            **extra,
            **self._common(acc),
        )

    def threat_actor(self, acc: AcceptedItem, item: ExtractedActor) -> stix2.ThreatActor:
        extra = {"aliases": item.aliases} if item.aliases else {}
        return stix2.ThreatActor(
            id=self._id("threat-actor", item.name.lower()),
            name=item.name,
            **extra,
            **self._common(acc),
        )

    def vulnerability(self, acc: AcceptedItem, item: ExtractedCVE) -> stix2.Vulnerability:
        return stix2.Vulnerability(
            id=self._id("vulnerability", item.cve_id),
            name=item.cve_id,
            description=item.context,
            external_references=[{"source_name": "cve", "external_id": item.cve_id}],
            **self._common(acc),
        )

    def relationship(self, source, rel_type: str, target) -> stix2.Relationship:
        return stix2.Relationship(
            id=self._id("relationship", f"{source.id}|{rel_type}|{target.id}"),
            relationship_type=rel_type,
            source_ref=source.id,
            target_ref=target.id,
            description="Inferred by the pipeline: the report names a single actor.",
            x_cti_agent_basis="single actor named in report",
            **self._common(),
        )

    def report(self, title: str, content: list) -> stix2.Report:
        p = self.p
        return stix2.Report(
            id=self._id("report", p.source_sha256),
            name=title or "Untitled report",
            description=(
                f"Extracted from {p.source_file} (sha256 {p.source_sha256[:12]}...) "
                "by cti-to-detection-agent. Pending human review."
            ),
            published=p.ingested_at,
            report_types=["threat-report"],
            object_refs=[o.id for o in content] or [TOOL_IDENTITY.id],
            **self._common(),
        )
