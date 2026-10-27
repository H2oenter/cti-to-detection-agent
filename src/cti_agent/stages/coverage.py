"""Stage 4a: tactic grouping, coverage against a rule set, and choosing what to hunt. No LLM."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from pathlib import Path

from cti_agent.attack.attack_index import AttackLookup
from cti_agent.models import AcceptedItem, CoverageEntry

# Kill-chain order across ATT&CK versions (v20 splits defense evasion into "stealth" and
# "defense-impairment"; older bundles still say "defense-evasion").
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]  # fmt: skip
PRE_COMPROMISE = {"reconnaissance", "resource-development"}


@dataclass(frozen=True)
class Rule:
    name: str
    technique_ids: frozenset[str]
    tables: tuple[str, ...]


def load_rules(path: Path) -> list[Rule]:
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    return [
        Rule(
            name=row["rule_name"].strip(),
            technique_ids=frozenset(t.strip().upper() for t in row["technique_ids"].split(";")),
            tables=tuple(t.strip() for t in row["tables"].split(";") if t.strip()),
        )
        for row in csv.DictReader(io.StringIO("\n".join(lines)))
    ]


def check_coverage(
    accepted: list[AcceptedItem], attack: AttackLookup, rules: list[Rule]
) -> list[CoverageEntry]:
    entries = []
    for item in accepted:
        if item.item_type != "technique":
            continue
        tid = item.item.attack_id
        info = attack.lookup(tid)
        if info is None:  # can't happen after validation, but don't guess if it does
            continue
        state, matched, note = _state(tid, info.domain, info.revoked_by, rules)
        entries.append(
            CoverageEntry(
                attack_id=tid,
                name=info.name,
                domain=info.domain,
                tactics=list(info.tactics),
                state=state,
                rules=matched,
                note=note,
                evidence_kind=item.evidence_kind,
            )
        )
    return entries


def _state(tid: str, domain: str, revoked_by: str | None, rules: list[Rule]):
    if domain == "mobile-attack":
        return "not_applicable", [], "Mobile ATT&CK: no Sentinel/Defender telemetry to hunt in"
    exact = [r.name for r in rules if tid in r.technique_ids]
    if exact:
        return "covered", exact, None
    if "." in tid:
        parent = tid.split(".")[0]
        on_parent = [r.name for r in rules if parent in r.technique_ids]
        if on_parent:
            return "partial", on_parent, f"rule covers the parent technique {parent} only"
    else:
        subs = sorted({t for r in rules for t in r.technique_ids if t.startswith(tid + ".")})
        if subs:
            on_subs = [r.name for r in rules if r.technique_ids & set(subs)]
            return "partial", on_subs, "rule covers sub-techniques only: " + ", ".join(subs)
    if revoked_by:
        replaced = [r.name for r in rules if revoked_by in r.technique_ids]
        if replaced:
            return "partial", replaced, f"covered under the replacement ID {revoked_by}"
    return "gap", [], None


def group_by_tactic(entries: list[CoverageEntry]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for entry in entries:
        for tactic in entry.tactics or ["(no tactic)"]:
            grouped.setdefault(tactic, []).append(entry.attack_id)
    return dict(sorted(grouped.items(), key=lambda kv: _tactic_rank(kv[0])))


def select_for_hunting(
    entries: list[CoverageEntry], cap: int
) -> tuple[list[CoverageEntry], list[str]]:
    """Gaps only, best hunting value first. Returns (chosen, left over).

    Order: techniques visible in enterprise telemetry before pre-compromise ones
    (reconnaissance and resource development happen outside your environment),
    explicit evidence before inferred, then kill-chain order.
    """
    gaps = [e for e in entries if e.state == "gap"]
    gaps.sort(
        key=lambda e: (
            bool(e.tactics) and set(e.tactics) <= PRE_COMPROMISE,
            e.evidence_kind != "explicit",
            min(map(_tactic_rank, e.tactics or [""])),
        )
    )
    return gaps[:cap], [e.attack_id for e in gaps[cap:]]


def _tactic_rank(tactic: str) -> int:
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)
