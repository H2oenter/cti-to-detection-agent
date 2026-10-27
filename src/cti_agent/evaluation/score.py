"""Scoring one ingest against one gold file. Plain set arithmetic, no model.

Two views of the same run: "validated" is what the pipeline accepted, "raw" is what the
model returned before the validator. The difference is the validator's contribution.
Optional gold items are ignored in both directions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from cti_agent.evaluation.gold import GoldReport
from cti_agent.models import ValidationResult
from cti_agent.stages.collector import ChunkResult
from cti_agent.stages.validator import normalise_value

EVIDENCE_FAILURES = {"quote_not_in_source", "value_not_in_quote"}


@dataclass
class PRF:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None if p is None or r is None else 0.0
        return 2 * p * r / (p + r)

    def __add__(self, other: PRF) -> PRF:
        return PRF(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    def as_dict(self) -> dict:
        return {**asdict(self), "precision": self.precision, "recall": self.recall, "f1": self.f1}


@dataclass
class ReportScore:
    report_id: str
    run_id: str
    indicators: PRF
    techniques: PRF
    raw_indicators: PRF
    raw_techniques: PRF
    evidence_pass_rate: float | None
    items_checked: int
    rejections: dict[str, int]
    false_positives: dict[str, list[str]] = field(default_factory=dict)
    false_negatives: dict[str, list[str]] = field(default_factory=dict)
    chunks_ok: int = 0
    chunks_total: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def as_dict(self) -> dict:
        data = asdict(self)
        for name in ("indicators", "techniques", "raw_indicators", "raw_techniques"):
            data[name] = getattr(self, name).as_dict()
        return data


def _compare(found: set, required: set, optional: set) -> tuple[PRF, list, list]:
    found = found - optional
    tp = found & required
    fp, fn = found - required, required - found
    return PRF(len(tp), len(fp), len(fn)), sorted(fp), sorted(fn)


def _label(key: tuple[str, str]) -> str:
    return f"{key[0]}:{key[1]}"


def score_report(
    gold: GoldReport, run_id: str, validation: ValidationResult, chunks: list[ChunkResult]
) -> ReportScore:
    required_ind = {i.key for i in gold.indicators}
    optional_ind = {i.key for i in gold.optional_indicators}
    required_tech, optional_tech = set(gold.techniques), set(gold.optional_techniques)

    accepted_ind = {
        (a.item.kind, a.item.value.lower())
        for a in validation.accepted
        if a.item_type == "indicator"
    }
    accepted_tech = {a.item.attack_id for a in validation.accepted if a.item_type == "technique"}
    raw_ind, raw_tech = set(), set()
    for chunk in chunks:
        if chunk.extraction is None:
            continue
        for ind in chunk.extraction.indicators:
            value = normalise_value(ind.kind, ind.value)  # an invalid value is still a miss
            raw_ind.add((ind.kind, (value or ind.value.strip()).lower()))
        raw_tech |= {t.attack_id.strip().upper() for t in chunk.extraction.techniques}

    indicators, ind_fp, ind_fn = _compare(accepted_ind, required_ind, optional_ind)
    techniques, tech_fp, tech_fn = _compare(accepted_tech, required_tech, optional_tech)
    raw_indicators, _, _ = _compare(raw_ind, required_ind, optional_ind)
    raw_techniques, _, _ = _compare(raw_tech, required_tech, optional_tech)

    rejections: dict[str, int] = validation.rejected_counts()
    checked = len(validation.accepted) + len(validation.rejected)
    failures = sum(n for reason, n in rejections.items() if reason in EVIDENCE_FAILURES)
    return ReportScore(
        report_id=gold.report_id,
        run_id=run_id,
        indicators=indicators,
        techniques=techniques,
        raw_indicators=raw_indicators,
        raw_techniques=raw_techniques,
        evidence_pass_rate=1 - failures / checked if checked else None,
        items_checked=checked,
        rejections=rejections,
        false_positives={"indicators": [_label(k) for k in ind_fp], "techniques": tech_fp},
        false_negatives={"indicators": [_label(k) for k in ind_fn], "techniques": tech_fn},
        chunks_ok=sum(c.outcome == "ok" for c in chunks),
        chunks_total=len(chunks),
    )
