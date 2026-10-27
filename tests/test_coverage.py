import pytest
from conftest import ROOT

from cti_agent.models import AcceptedItem, CoverageEntry, Evidence, ExtractedTechnique
from cti_agent.stages.coverage import (
    Rule,
    check_coverage,
    group_by_tactic,
    load_rules,
    select_for_hunting,
)


def technique(tid: str, kind: str = "explicit") -> AcceptedItem:
    return AcceptedItem(
        item_type="technique",
        item=ExtractedTechnique(attack_id=tid, behaviour="b", evidence=Evidence(quote="q")),
        evidence_kind=kind,
        item_hash="sha256:x",
    )


def rule(name: str, *tids: str) -> Rule:
    return Rule(name=name, technique_ids=frozenset(tids), tables=("DeviceProcessEvents",))


def test_sample_rules_load_and_skip_comments():
    rules = load_rules(ROOT / "data" / "my_rules.sample.csv")
    assert rules and all(r.name.startswith("FICTIONAL") for r in rules)
    assert "T1621" in rules[0].technique_ids


@pytest.mark.parametrize(
    ("tid", "rules", "state", "note"),
    [
        ("T1621", [rule("mfa", "T1621")], "covered", None),
        ("T1566.004", [rule("phish", "T1566")], "partial", "parent technique T1566"),
        ("T1078", [rule("cloud", "T1078.004")], "partial", "sub-techniques only: T1078.004"),
        ("T1086", [rule("ps", "T1059.001")], "partial", "replacement ID T1059.001"),
        ("T1486", [rule("mfa", "T1621")], "gap", None),
        ("T1660", [rule("phish", "T1660")], "not_applicable", "Mobile ATT&CK"),
    ],
)
def test_coverage_states(attack_index, tid, rules, state, note):
    [entry] = check_coverage([technique(tid)], attack_index, rules)
    assert entry.state == state
    if note:
        assert note in entry.note


def entry(tid, tactics, kind="explicit", state="gap"):
    return CoverageEntry(
        attack_id=tid, name=tid, domain="enterprise-attack", tactics=tactics, state=state,
        evidence_kind=kind,
    )  # fmt: skip


def test_selection_order_and_cap():
    entries = [
        entry("T1589", ["reconnaissance"]),  # pre-compromise: last
        entry("T1486", ["impact"]),
        entry("T1219", ["command-and-control"], kind="inferred"),
        entry("T1078", ["initial-access", "persistence"]),
        entry("T1621", ["credential-access"], state="covered"),  # not a gap
    ]
    chosen, left = select_for_hunting(entries, cap=2)
    assert [e.attack_id for e in chosen] == ["T1078", "T1486"]
    assert left == ["T1219", "T1589"]


def test_group_by_tactic_follows_kill_chain():
    grouped = group_by_tactic(
        [entry("T1486", ["impact"]), entry("T1078", ["persistence", "initial-access"])]
    )
    assert list(grouped) == ["initial-access", "persistence", "impact"]
