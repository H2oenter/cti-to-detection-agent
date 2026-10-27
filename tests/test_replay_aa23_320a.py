"""Replays the real model output recorded from CISA AA23-320A.

Ingest: claude-haiku-5-5, 26 Oct 2026. Analysis and review: claude-sonnet-5-5, 27 Oct 2026.
The model's answers are fixed, so this guards everything around the model calls: chunking and
prompt building (the request keys depend on them), validation, coverage, lint, the attention
logic and the outputs. See fixtures/reports/README.md.
"""

import pytest
from conftest import FIXTURES, ROOT

from cti_agent.attack.attack_index import AttackIndex
from cti_agent.config import Settings
from cti_agent.llm.client import ReplayClient
from cti_agent.pipeline import run_analyse, run_ingest

REPORT = FIXTURES / "reports" / "aa23-320a.txt"
RECORDED = FIXTURES / "llm" / "aa23-320a"
RECORDED_ANALYSIS = FIXTURES / "llm" / "aa23-320a-analyse"


@pytest.fixture(scope="module")
def settings(tmp_path_factory):
    return Settings(
        _env_file=None,
        out_dir=tmp_path_factory.mktemp("out"),
        allowlist_file=ROOT / "data" / "allowlist.txt",
        rules_file=ROOT / "data" / "my_rules.sample.csv",
        kql_schema_file=ROOT / "data" / "kql_schema.json",
    )


@pytest.fixture(scope="module")
def attack():
    return AttackIndex(
        FIXTURES / "attack-v20-subset-aa23-320a.json",
        FIXTURES / "attack-mobile-v20-subset-aa23-320a.json",
    )


@pytest.fixture(scope="module")
def result(settings, attack):
    return run_ingest(REPORT, "CLEAR", settings, ReplayClient(RECORDED), attack=attack)


@pytest.fixture(scope="module")
def analysis(result, settings, attack):
    return run_analyse(result.run_id, settings, ReplayClient(RECORDED_ANALYSIS), attack=attack)


def by_type(result, item_type):
    return [a for a in result.validation.accepted if a.item_type == item_type]


def rejected(result, reason, field):
    return sorted(r.item[field] for r in result.validation.rejected if r.reason == reason)


def test_run_is_complete_and_no_evidence_failed(result):
    assert result.summary.status == "complete"
    assert result.summary.chunks_done == 2
    evidence_failures = {"quote_not_in_source", "value_not_in_quote", "suspected_injection"}
    assert not [r for r in result.validation.rejected if r.reason in evidence_failures]


def test_actor_and_aliases(result):
    [actor] = by_type(result, "actor")
    assert actor.item.name == "Scattered Spider"
    assert {"UNC3944", "Octo Tempest", "Muddled Libra", "Storm-0875"} <= set(actor.item.aliases)


def test_placeholder_domains_do_not_become_indicators(result):
    assert by_type(result, "indicator") == []
    placeholders = rejected(result, "placeholder_pattern", "value")
    assert len(placeholders) == 6
    assert "targetsname-sso.com" in placeholders and "oktalogin-targetcompany.com" in placeholders


def test_techniques(result):
    accepted = {a.item.attack_id for a in by_type(result, "technique")}
    assert len(accepted) == 41
    assert {"T1621", "T1566.004", "T1219", "T1486", "T1567.002"} <= accepted
    assert rejected(result, "unknown_technique", "attack_id") == []


def test_mobile_techniques_accepted_with_coverage_warning(result):
    mobile = {a.item.attack_id: a for a in by_type(result, "technique")
              if a.item.attack_id in ("T1660", "T1451")}  # fmt: skip
    assert sorted(mobile) == ["T1451", "T1660"]  # smishing and SIM swap
    for item in mobile.values():
        assert any("Mobile ATT&CK" in w and "limited" in w for w in item.warnings)


def test_revoked_technique_carries_its_replacement(result):
    [t1656] = [a for a in by_type(result, "technique") if a.item.attack_id == "T1656"]
    assert t1656.warnings == ["T1656 is revoked in ATT&CK; replaced by T1684.001"]


def test_accepted_items_carry_their_surrounding_text(result):
    for item in result.validation.accepted:
        assert item.context and len(item.context) > len(item.item.evidence.quote)


# --- analysis (stages 4-5), replayed -------------------------------------------------------


def test_analysis_coverage(analysis):
    states = [e.state for e in analysis.coverage]
    assert (states.count("covered"), states.count("partial"), states.count("gap")) == (5, 2, 32)
    assert states.count("not_applicable") == 2


def test_analysis_drafts_reviewed_and_linted(analysis):
    assert [h.technique_id for h in analysis.hunts] == [
        "T1199", "T1204", "T1648", "T1556.006", "T1136"
    ]  # fmt: skip
    assert all(h.review is not None for h in analysis.hunts)
    assert all(not h.lint_failed for h in analysis.hunts)  # incl. the RegTime regression
    flagged = {h.technique_id: h.attention_reasons for h in analysis.hunts if h.needs_attention}
    assert flagged == {"T1648": ["kql_correct scored 2"]}


def test_analysis_leadership_summary_passed_the_fact_check(analysis):
    assert analysis.summary_source == "model"
    assert "41" in analysis.leadership_summary and "32" in analysis.leadership_summary
