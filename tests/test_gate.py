"""The human gate: decisions, edits, bulk decisions and the approved/ folder."""

import json

import pytest
import stix2
from conftest import FIXTURE_REPORT, FakeAnalyst, FakeModel

from cti_agent.audit import AuditChainBroken, AuditLog
from cti_agent.pipeline import run_analyse, run_ingest
from cti_agent.stages.gate import Gate, GateError

CLEAN_QUERY = """DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe" and FileName =~ "mshta.exe"
| project Timestamp, DeviceName, ProcessCommandLine"""


def audit_for(settings):
    return AuditLog(settings.out_dir / "audit.jsonl", settings.db_path)


@pytest.fixture
def gate(settings, aa23_run, aa23_attack):
    """AA23-320A analysed with fake models; the T1204 draft carries an externaldata query."""
    run_analyse(aa23_run, settings, FakeAnalyst(bad_query_for={"T1204"}), attack=aa23_attack)
    return Gate(settings, aa23_run, "sam", audit_for(settings))


def hunts(gate):
    return [i for i in gate.items if i.kind == "hunt"]


def test_items_come_hunts_first(gate):
    kinds = [i.kind for i in gate.items]
    assert kinds[:5] == ["hunt"] * 5
    assert kinds[5] == "threat-actor" and set(kinds[6:]) == {"attack-pattern"}
    assert gate.items[0].ref.startswith("draft:") and gate.items[5].ref.startswith("stix:")


def test_decisions_are_logged_against_the_exact_content(gate, settings):
    first, _, third, *_ = hunts(gate)
    gate.decide(first, "approve")
    gate.decide(third, "reject", reason="too broad for this environment")

    rows = gate.audit.entries(gate.run_id)
    assert [(r["item_ref"], r["decision"]) for r in rows] == [
        (first.ref, "approve"), (third.ref, "reject")
    ]  # fmt: skip
    assert rows[0]["item_hash"] == first.hunt.item_hash and rows[0]["actor"] == "sam"
    assert gate.status(first) == "approved" and gate.status(third) == "rejected"

    approved = list((gate.out_dir / "approved" / "hunts").iterdir())
    assert [p.name for p in approved] == [f"{first.hunt.draft_id}.kql"]
    assert approved[0].read_text(encoding="utf-8").startswith("// APPROVED by sam at ")
    assert third not in gate.pending() and first not in gate.pending()


def test_rejection_needs_a_reason(gate):
    with pytest.raises(GateError, match="reason"):
        gate.decide(hunts(gate)[0], "reject", reason="  ")


def test_lint_failed_draft_must_be_edited_before_approval(gate):
    bad = next(i for i in hunts(gate) if i.hunt.technique_id == "T1204")
    with pytest.raises(GateError, match="lint errors"):
        gate.decide(bad, "approve")

    fixed = gate.edit_hunt(bad, CLEAN_QUERY)
    assert not fixed.hunt.lint_failed and fixed.hash != bad.hash
    assert any("edited by sam" in r for r in fixed.hunt.attention_reasons)
    gate.decide(fixed, "approve")

    edit = next(r for r in gate.audit.entries() if r["action"] == "edit")
    assert edit["detail"]["previous_hash"] == bad.hash and edit["item_hash"] == fixed.hash
    # The edited version is what's stored now.
    assert Gate(gate.settings, gate.run_id, "sam", gate.audit).item(bad.ref).hash == fixed.hash


def test_editing_an_approved_item_needs_a_new_decision(gate):
    item = hunts(gate)[0]
    gate.decide(item, "approve")
    edited = gate.edit_hunt(item, CLEAN_QUERY)
    assert gate.status(edited) == "changed" and edited in gate.pending()
    assert not list((gate.out_dir / "approved" / "hunts").iterdir())


def test_rest_of_type_is_logged_per_item(gate):
    patterns = [i for i in gate.items if i.kind == "attack-pattern"]
    count = gate.decide_rest_of_type(patterns[0], "approve", None)
    assert count == len(patterns) == 41  # incl. the two Mobile techniques
    bulk = [r for r in gate.audit.entries() if r["bulk"]]
    assert len(bulk) == 41 and {r["item_ref"] for r in bulk} == {p.ref for p in patterns}
    with pytest.raises(GateError, match="one at a time"):
        gate.decide_rest_of_type(hunts(gate)[0], "approve", None)


def test_approved_bundle_has_only_approved_objects_and_their_links(gate):
    actor = next(i for i in gate.items if i.kind == "threat-actor")
    patterns = [i for i in gate.items if i.kind == "attack-pattern"]
    gate.decide(actor, "approve")
    gate.decide(patterns[0], "approve")
    gate.decide(patterns[1], "reject", reason="not this actor")

    bundle = json.loads((gate.out_dir / "approved" / "stix-bundle.json").read_text("utf-8"))
    stix2.parse(json.dumps(bundle), allow_custom=True)
    ids = {o["id"] for o in bundle["objects"]}
    assert {actor.stix["id"], patterns[0].stix["id"]} <= ids and patterns[1].stix["id"] not in ids
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert [(r["source_ref"], r["target_ref"]) for r in rels] == [
        (actor.stix["id"], patterns[0].stix["id"])
    ]
    assert {o["type"] for o in bundle["objects"]} >= {"identity", "marking-definition"}


@pytest.fixture
def indicator_gate(settings, attack_index):
    run = run_ingest(FIXTURE_REPORT, "CLEAR", settings, FakeModel(), attack=attack_index)
    return Gate(settings, run.run_id, "sam", audit_for(settings))


def test_stix_edit_keeps_provenance(indicator_gate):
    item = next(i for i in indicator_gate.items if i.kind == "indicator")
    obj = dict(item.stix, description="Phishing page seen in March 2026")
    edited = indicator_gate.edit_stix(item, json.dumps(obj))
    assert edited.stix["x_cti_agent_edited_by"] == "sam"
    assert edited.stix["modified"] > item.stix["modified"]
    assert edited.stix["x_cti_agent_evidence_quote"] == item.stix["x_cti_agent_evidence_quote"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", "indicator--00000000-0000-4000-8000-000000000000", "can't be edited"),
        ("x_cti_agent_evidence_quote", "a different quote", "can't be edited"),
        ("pattern", "[not a pattern", "isn't valid STIX"),
    ],
)
def test_stix_edit_refuses_bad_changes(indicator_gate, field, value, message):
    item = next(i for i in indicator_gate.items if i.kind == "indicator")
    with pytest.raises(GateError, match=message):
        indicator_gate.edit_stix(item, json.dumps(dict(item.stix, **{field: value})))


def test_a_tampered_audit_log_stops_the_gate(gate, settings):
    gate.decide(hunts(gate)[0], "approve")
    path = settings.out_dir / "audit.jsonl"
    path.write_text(path.read_text(encoding="utf-8").replace('"sam"', '"mallory"'), "utf-8")
    with pytest.raises(AuditChainBroken):
        Gate(settings, gate.run_id, "sam", audit_for(settings))
