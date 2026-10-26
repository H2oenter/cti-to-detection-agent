from datetime import UTC, datetime, timedelta

import stix2

from cti_agent.models import (
    AcceptedItem,
    Evidence,
    ExtractedActor,
    ExtractedIndicator,
    ExtractedTechnique,
    Provenance,
    ValidationResult,
)
from cti_agent.outputs.stix_out import TLP_MARKINGS, build_bundle, stix_pattern

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def provenance(tlp="CLEAR") -> Provenance:
    return Provenance(
        source_file="fixture.txt",
        source_sha256="a" * 64,
        tlp=tlp,
        ingested_at=NOW,
        run_id="run-1",
        prompt_version="collector@v1",
        model="claude-haiku-5-5",
    )


def accepted(item, item_type, kind="explicit", page=None, warnings=()):
    return AcceptedItem(
        item_type=item_type,
        item=item,
        evidence_kind=kind,
        page=page,
        warnings=list(warnings),
        item_hash="sha256:" + "b" * 64,
    )


def actor(name):
    return accepted(ExtractedActor(name=name, evidence=Evidence(quote=name)), "actor")


INDICATOR = accepted(
    ExtractedIndicator(
        kind="url",
        value="https://bad-fixture.net/it's",
        context="phishing",
        evidence=Evidence(quote="hxxps://bad-fixture[.]net/it's"),
    ),
    "indicator",
    page=3,
)
TECHNIQUE = accepted(
    ExtractedTechnique(attack_id="T1621", behaviour="MFA fatigue", evidence=Evidence(quote="q")),
    "technique",
    kind="inferred",
    warnings=["note"],
)


def test_pattern_escaping():
    assert stix_pattern("url", "http://a/it's") == "[url:value = 'http://a/it\\'s']"
    assert stix_pattern("sha256", "ab") == "[file:hashes.'SHA-256' = 'ab']"
    assert stix_pattern("domain", "a\\b") == "[domain-name:value = 'a\\\\b']"


def test_bundle_carries_provenance_and_evidence(attack_index):
    validation = ValidationResult(accepted=[actor("Fixture Spider"), INDICATOR, TECHNIQUE])
    bundle = build_bundle(validation, provenance(), "Fixture report", attack_index)
    by_type = {o["type"]: o for o in bundle.objects}

    ind = by_type["indicator"]
    assert ind["valid_until"] - ind["valid_from"] == timedelta(days=90)
    assert ind["x_cti_agent_evidence_quote"] == "hxxps://bad-fixture[.]net/it's"
    assert ind["x_cti_agent_evidence_page"] == 3
    assert ind["x_cti_agent_run_id"] == "run-1"
    assert ind["x_cti_agent_item_hash"].startswith("sha256:")

    ap = by_type["attack-pattern"]
    assert ap["name"] == "Multi-Factor Authentication Request Generation"
    assert ap["external_references"][0]["external_id"] == "T1621"
    assert ap["kill_chain_phases"][0]["phase_name"] == "credential-access"
    assert ap["x_cti_agent_evidence_kind"] == "inferred"
    assert "x_cti_agent_evidence_page" not in ap

    rels = sorted(o["relationship_type"] for o in bundle.objects if o["type"] == "relationship")
    assert rels == ["indicates", "uses"]
    assert by_type["report"]["name"] == "Fixture report"


def test_no_relationships_when_several_actors(attack_index):
    validation = ValidationResult(accepted=[actor("Group A"), actor("Group B"), INDICATOR])
    bundle = build_bundle(validation, provenance(), "t", attack_index)
    assert not [o for o in bundle.objects if o["type"] == "relationship"]


def test_tlp_marking_and_label(attack_index):
    bundle = build_bundle(
        ValidationResult(accepted=[INDICATOR]), provenance("AMBER+STRICT"), "t", attack_index
    )
    ind = next(o for o in bundle.objects if o["type"] == "indicator")
    assert ind["object_marking_refs"] == [TLP_MARKINGS["AMBER"].id]
    assert ind["x_cti_agent_tlp"] == "AMBER+STRICT"


def test_empty_run_still_makes_a_valid_bundle(attack_index):
    bundle = build_bundle(ValidationResult(), provenance(), "", attack_index)
    stix2.parse(bundle.serialize(), allow_custom=True)
    report = next(o for o in bundle.objects if o["type"] == "report")
    assert report["name"] == "Untitled report"
