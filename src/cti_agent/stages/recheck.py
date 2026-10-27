"""The indicator re-check: a second, stronger model says what role each accepted indicator
plays in the report, and code decides what that means. No tools, one call per batch.

It runs after the validator, which has already proved every value is in the report and in its
own quote. What the validator can't tell is whether the report presents the value as an
indicator at all, or as a naming pattern, a contact address, a reference or a file name.

It can only take away: an item is kept, kept with a warning, or rejected. It can't add an
item or change a value, so the worst a planted instruction can do is drop real items, and
those show up in rejected.jsonl with the role that removed them. The model's own words go to
recheck.json only, never into a warning or a STIX object, which can be published.
"""

from __future__ import annotations

from dataclasses import dataclass

from cti_agent.config import Settings
from cti_agent.llm.client import LLMClient
from cti_agent.llm.prompting import Prompt
from cti_agent.llm.steps import outcome_of, traced_call
from cti_agent.models import AcceptedItem, Rejection, RoleCheck, ValidationResult
from cti_agent.stages.collector import wrap_untrusted
from cti_agent.trace import Tracer

BATCH_SIZE = 25
KEEP = {"attacker_indicator"}
FLAG = {"unclear"}
# Warnings are written by code, from this fixed set, because they end up in STIX.
NO_ANSWER = "re-check gave no role for this indicator; look at it before approving"
UNCLEAR = "re-check couldn't tell from the text whether this is an indicator; look before approving"
NOT_RUN = "re-check didn't run ({outcome}); look at this indicator before approving"


@dataclass
class RecheckRecord:
    id: str
    kind: str
    value: str
    role: str | None
    reason: str | None  # the model's words: for recheck.json only
    outcome: str


def item_id(accepted: AcceptedItem) -> str:
    """A short id from the item's own hash: stable however the batch is ordered."""
    return accepted.item_hash.split(":", 1)[-1][:12]


def recheck_user(batch: list[AcceptedItem]) -> str:
    blocks = []
    for a in batch:
        blocks.append(
            f"[id {item_id(a)}] {a.item.kind} {a.item.value}\n"
            f"quote: {a.item.evidence.quote}\n"
            f"around it: {a.context or '(no surrounding text)'}"
        )
    return f"Items to check: {len(batch)}\n\n" + wrap_untrusted("\n\n".join(blocks))


def recheck(
    validation: ValidationResult,
    *,
    client: LLMClient,
    tracer: Tracer,
    settings: Settings,
    prompt: Prompt,
) -> tuple[ValidationResult, list[RecheckRecord]]:
    """Returns the validation with non-indicators moved to rejected and doubtful ones
    flagged, plus a record of every verdict."""
    indicators = [a for a in validation.accepted if a.item_type == "indicator"]
    if not indicators:
        return validation, []
    verdicts: dict[str, tuple[str, str]] = {}
    outcomes: dict[str, str] = {}
    batches = [indicators[i : i + BATCH_SIZE] for i in range(0, len(indicators), BATCH_SIZE)]
    for n, batch in enumerate(batches, start=1):
        ids = {item_id(a) for a in batch}
        result = traced_call(
            client=client, tracer=tracer, stage="recheck", step=f"batch {n}/{len(batches)}",
            model=settings.recheck_model, system=prompt.text, user=recheck_user(batch),
            schema=RoleCheck, max_tokens=settings.recheck_max_output_tokens,
            effort=settings.recheck_effort, refusal_fallback=True,
        )  # fmt: skip
        outcome = "skipped_budget" if result is None else outcome_of(result)
        for i in ids:
            outcomes[i] = outcome
        if result is not None and result.parsed is not None:
            for v in result.parsed.verdicts:
                if v.id in ids and v.id not in verdicts:  # unknown ids and repeats are ignored
                    verdicts[v.id] = (v.role, v.reason)

    accepted, rejected, records = [], list(validation.rejected), []
    for a in validation.accepted:
        if a.item_type != "indicator":
            accepted.append(a)
            continue
        i = item_id(a)
        role, reason = verdicts.get(i, (None, None))
        records.append(RecheckRecord(i, a.item.kind, a.item.value, role, reason, outcomes[i]))
        if role is None:
            note = NO_ANSWER if outcomes[i] == "ok" else NOT_RUN.format(outcome=outcomes[i])
            accepted.append(a.model_copy(update={"warnings": [*a.warnings, note]}))
        elif role in KEEP:
            accepted.append(a.model_copy(update={"recheck_role": role}))
        elif role in FLAG:
            accepted.append(
                a.model_copy(update={"recheck_role": role, "warnings": [*a.warnings, UNCLEAR]})
            )
        else:
            rejected.append(
                Rejection(
                    item_type=a.item_type,
                    item=a.item.model_dump(mode="json"),
                    reason="not_an_indicator",
                    detail=f"re-check: {role.replace('_', ' ')} ({reason})",
                )
            )
    return ValidationResult(accepted=accepted, rejected=rejected), records
