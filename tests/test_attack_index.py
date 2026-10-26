import pytest
from conftest import FIXTURES

from cti_agent.attack.attack_index import AttackIndex


def test_lookup_says_which_matrix_answered(attack_index):
    enterprise = attack_index.lookup("t1621")
    mobile = attack_index.lookup("T1660")
    assert enterprise.domain == "enterprise-attack" and enterprise.kill_chain == "mitre-attack"
    assert mobile.domain == "mobile-attack" and mobile.kill_chain == "mitre-mobile-attack"
    assert mobile.tactics == ("initial-access",)
    assert attack_index.lookup("T9999") is None


def test_description_lists_loaded_matrices(attack_index):
    assert attack_index.description == "enterprise-attack, mobile-attack"


def test_enterprise_only_still_works():
    index = AttackIndex(FIXTURES / "attack-mini.json")
    assert index.description == "enterprise-attack"
    assert index.lookup("T1660") is None


def test_missing_bundle_says_how_to_fetch(tmp_path):
    with pytest.raises(FileNotFoundError, match=r"fetch_attack\.py"):
        AttackIndex(tmp_path / "missing.json")
