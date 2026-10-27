"""The indicator re-check: roles become keep, flag or reject in code, and nothing is added."""

import io
import json

import pytest
from conftest import FIXTURE_REPORT, FakeModel
from rich.console import Console

from cti_agent.audit import AuditLog
from cti_agent.llm.client import LLMResult
from cti_agent.llm.prompting import load_prompt
from cti_agent.models import (
    AcceptedItem,
    Evidence,
    ExtractedIndicator,
    RoleCheck,
    RoleVerdict,
    ValidationResult,
)
from cti_agent.pipeline import run_ingest
from cti_agent.review_ui import run_review
from cti_agent.stages.gate import Gate, GateError
from cti_agent.stages.recheck import BATCH_SIZE, NOT_RUN, UNCLEAR, item_id, recheck
from cti_agent.trace import Tracer
from cti_agent.util.normalise import item_hash

ROLES = {
    "support-sso-fixture.com": "placeholder_or_example",  # rejected
    "198.51.101.7": "unclear",  # kept, flagged
}


def ingest(settings, attack_index, model):
    return run_ingest(FIXTURE_REPORT, "CLEAR", settings, model, attack=attack_index)


def test_roles_keep_flag_or_reject(settings, attack_index):
    result = ingest(settings, attack_index, FakeModel(roles=ROLES))
    kept = {a.item.value: a for a in result.validation.accepted if a.item_type == "indicator"}
    assert "support-sso-fixture.com" not in kept
    [rejection] = [r for r in result.validation.rejected if r.reason == "not_an_indicator"]
    assert rejection.item["value"] == "support-sso-fixture.com"
    assert rejection.detail.startswith("re-check: placeholder or example")
    assert kept["198.51.101.7"].warnings == [UNCLEAR]
    url = kept["https://helpdesk-reset-fixture.net/login"]
    assert url.recheck_role == "attacker_indicator" and url.warnings == []

    out = result.out_dir
    records = json.loads((out / "recheck.json").read_text(encoding="utf-8"))
    assert {r["role"] for r in records} == {"attacker_indicator", "placeholder_or_example",
                                            "unclear"}  # fmt: skip
    bundle = (out / "bundle.json").read_text(encoding="utf-8")
    assert '"x_cti_agent_recheck_role": "attacker_indicator"' in bundle
    assert "fake verdict" not in bundle  # the model's words stay in recheck.json
    rejected = (out / "rejected.jsonl").read_text(encoding="utf-8")
    assert "not_an_indicator" in rejected


def accepted(n: int) -> list[AcceptedItem]:
    items = []
    for i in range(n):
        ind = ExtractedIndicator(kind="ipv4", value=f"198.51.100.{i}", context="c",
                                 evidence=Evidence(quote=f"198.51.100.{i} (C2)"))  # fmt: skip
        items.append(AcceptedItem(item_type="indicator", item=ind, evidence_kind="explicit",
                                  item_hash=item_hash(ind)))  # fmt: skip
    return items


class Scripted:
    """A re-check model that answers with whatever verdicts it is given."""

    def __init__(self, verdicts=None, stop_reason="end_turn"):
        self.verdicts, self.stop_reason, self.users = verdicts or {}, stop_reason, []

    def structured(self, *, model, system, user, schema, max_tokens, effort=None, **kwargs):
        assert schema is RoleCheck
        self.users.append(user)
        if self.stop_reason != "end_turn":
            return LLMResult(None, self.stop_reason, 900, 0, 5, model, "simulated")
        return LLMResult(RoleCheck(verdicts=self.verdicts(user)), "end_turn", 900, 200, 5, model)


def run(settings, tmp_path, validation, model):
    tracer = Tracer("r", tmp_path / "trace.jsonl", settings)
    return recheck(validation, client=model, tracer=tracer, settings=settings,
                   prompt=load_prompt("recheck"))  # fmt: skip


def test_it_never_adds_an_item_or_changes_a_value(settings, tmp_path):
    items = accepted(2)
    first = item_id(items[0])

    def verdicts(user):
        return [
            RoleVerdict(id=first, role="attacker_indicator", reason="c2"),
            RoleVerdict(id=first, role="reference", reason="a repeat is ignored"),
            RoleVerdict(id="0123456789ab", role="attacker_indicator", reason="not shown"),
        ]

    result, records = run(settings, tmp_path, ValidationResult(accepted=items),
                          Scripted(verdicts))  # fmt: skip
    assert [a.item.value for a in result.accepted] == [a.item.value for a in items]
    assert result.accepted[0].recheck_role == "attacker_indicator"
    assert result.accepted[1].warnings and result.accepted[1].recheck_role is None  # no answer
    assert {r.id for r in records} == {item_id(a) for a in items}


@pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens"])
def test_a_failed_recheck_keeps_everything_with_a_warning(settings, tmp_path, stop_reason):
    items = accepted(3)
    result, _ = run(settings, tmp_path, ValidationResult(accepted=items),
                    Scripted(stop_reason=stop_reason))  # fmt: skip
    assert len(result.accepted) == 3 and result.rejected == []
    outcome = {"refusal": "refused", "max_tokens": "truncated"}[stop_reason]
    assert all(a.warnings == [NOT_RUN.format(outcome=outcome)] for a in result.accepted)


def test_batches_are_keyed_by_hash_not_position(settings, tmp_path):
    items = accepted(BATCH_SIZE + 5)
    model = Scripted(lambda user: [
        RoleVerdict(id=i, role="attacker_indicator", reason="r")
        for i in reversed([item_id(a) for a in items])  # every id, in reverse order
    ])  # fmt: skip
    result, _ = run(settings, tmp_path, ValidationResult(accepted=items), model)
    assert len(model.users) == 2
    assert all(a.recheck_role == "attacker_indicator" for a in result.accepted)


def test_no_indicators_no_call_and_it_can_be_turned_off(settings, tmp_path, attack_index):
    model = Scripted()
    _, records = run(settings, tmp_path, ValidationResult(), model)
    assert records == [] and model.users == []
    off = settings.model_copy(update={"recheck_indicators": False})
    fake = FakeModel(roles=ROLES)
    ingest(off, attack_index, fake)
    assert fake.recheck_calls == []


# --- the gate: indicators that passed both checks, approved as one list ---------------------


@pytest.fixture
def gate(settings, attack_index):
    run_id = ingest(settings, attack_index, FakeModel(roles=ROLES)).run_id
    return Gate(settings, run_id, "sam", AuditLog(settings.out_dir / "audit.jsonl",
                                                  settings.db_path))  # fmt: skip


def test_clean_indicators_are_approved_as_the_listed_set(gate):
    clean = gate.clean_indicators()
    names = sorted(i.stix["name"] for i in clean)
    assert names == sorted([
        "https://helpdesk-reset-fixture.net/login",
        "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
    ])  # fmt: skip
    with pytest.raises(GateError, match="changed since"):
        gate.approve_clean_indicators([clean[0].ref])  # a stale or partial list
    assert gate.approve_clean_indicators([i.ref for i in clean]) == 2
    rows = [r for r in gate.audit.entries() if r["bulk"]]
    assert sorted(r["item_ref"] for r in rows) == sorted(i.ref for i in clean)
    flagged = next(i for i in gate.items if i.stix and i.stix.get("name") == "198.51.101.7")
    assert gate.status(flagged) == "pending"
    with pytest.raises(GateError, match="one at a time"):
        gate.decide(flagged, "approve", bulk=True)


def test_review_offers_the_list_on_a_clean_indicator(gate):
    keys = iter(["A", "y", "s", "q"])
    asked = []

    def ask(prompt, choices):
        asked.append((prompt, choices))
        return next(keys)

    out = io.StringIO()
    counts = run_review(gate, Console(file=out, width=120), ask=ask, ask_text=lambda p: "",
                        edit=lambda text, ext: None)  # fmt: skip
    assert counts["approved"] == 2
    assert "[A]pprove all 2 indicators that passed both checks" in asked[0][0]
    assert asked[1] == ("Approve these 2 indicators?", ["y", "n"])
    assert "Indicators that passed the validator and the re-check" in out.getvalue()
    assert "A" not in asked[2][1]  # the flagged one: no list approval offered
