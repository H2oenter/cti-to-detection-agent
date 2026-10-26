"""Replays the real model output recorded from CISA AA23-320A (claude-haiku-5-5, 26 Oct 2026).

The model's answers are fixed, so this guards everything after the model call: chunking (the
request keys depend on it), validation and the STIX bundle. See fixtures/reports/README.md.
"""

import pytest
from conftest import FIXTURES, ROOT

from cti_agent.attack.attack_index import AttackIndex
from cti_agent.config import Settings
from cti_agent.llm.client import ReplayClient
from cti_agent.pipeline import run_ingest

REPORT = FIXTURES / "reports" / "aa23-320a.txt"
RECORDED = FIXTURES / "llm" / "aa23-320a"


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    settings = Settings(
        _env_file=None,
        out_dir=tmp_path_factory.mktemp("out"),
        allowlist_file=ROOT / "data" / "allowlist.txt",
    )
    attack = AttackIndex(FIXTURES / "attack-v20-subset-aa23-320a.json")
    return run_ingest(REPORT, "CLEAR", settings, ReplayClient(RECORDED), attack=attack)


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
    assert len(accepted) == 39
    assert {"T1621", "T1566.004", "T1219", "T1486", "T1567.002"} <= accepted
    # Mobile ATT&CK IDs the advisory cites; the Enterprise bundle doesn't have them.
    assert rejected(result, "unknown_technique", "attack_id") == ["T1451", "T1660"]


def test_revoked_technique_carries_its_replacement(result):
    [t1656] = [a for a in by_type(result, "technique") if a.item.attack_id == "T1656"]
    assert t1656.warnings == ["T1656 is revoked in ATT&CK; replaced by T1684.001"]
