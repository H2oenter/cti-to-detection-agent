from pathlib import Path

import pytest

from cti_agent.attack.attack_index import AttackIndex
from cti_agent.stages.validator import Allowlist

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def attack_index() -> AttackIndex:
    return AttackIndex(FIXTURES / "attack-mini.json")


@pytest.fixture(scope="session")
def allowlist() -> Allowlist:
    return Allowlist.load(ROOT / "data" / "allowlist.txt")
