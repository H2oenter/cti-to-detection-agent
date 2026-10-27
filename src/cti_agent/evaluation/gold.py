"""Gold labels: what a person says a report contains. The eval scores the pipeline against them.

A gold file is pinned to one version of a report by its SHA-256, because CISA updates
advisories. Indicator values are normalised exactly as the validator normalises them,
so a match is a match and not a formatting accident.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator

from cti_agent.models import IndicatorKind
from cti_agent.stages.validator import normalise_value

TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class GoldError(Exception):
    pass


class GoldIndicator(BaseModel):
    kind: IndicatorKind
    value: str

    @model_validator(mode="after")
    def _normalise(self) -> GoldIndicator:
        normalised = normalise_value(self.kind, self.value)
        if normalised is None:
            raise ValueError(f"{self.value!r} is not a valid {self.kind}")
        self.value = normalised
        return self

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, self.value.lower())


class GoldSource(BaseModel):
    url: str | None = None
    file: str
    sha256: str


class GoldReport(BaseModel):
    report_id: str
    title: str = ""
    source: GoldSource
    labelled_by: str
    labelled_on: str
    indicators: list[GoldIndicator] = Field(default_factory=list)
    optional_indicators: list[GoldIndicator] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    optional_techniques: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("labelled_by", "labelled_on")
    @classmethod
    def _signed(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a gold file needs labelled_by and labelled_on: it's a person's call")
        return value

    @field_validator("techniques", "optional_techniques")
    @classmethod
    def _techniques(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip().upper() for v in values]
        if bad := [v for v in cleaned if not TECHNIQUE.match(v)]:
            raise ValueError(f"not technique IDs: {bad}")
        return cleaned

    @field_validator("cves")
    @classmethod
    def _cves(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip().upper() for v in values]
        if bad := [v for v in cleaned if not CVE.match(v)]:
            raise ValueError(f"not CVE IDs: {bad}")
        return cleaned

    @model_validator(mode="after")
    def _no_overlap(self) -> GoldReport:
        both = {i.key for i in self.indicators} & {i.key for i in self.optional_indicators}
        both_t = set(self.techniques) & set(self.optional_techniques)
        if both or both_t:
            raise ValueError(
                f"listed as both required and optional: {sorted(both) + sorted(both_t)}"
            )
        return self


def load_gold(directory: Path) -> list[GoldReport]:
    """Every reviewed gold file in a folder. Drafts (*.draft.json) are never scored."""
    reports = []
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith(".draft.json"):
            continue
        try:
            reports.append(GoldReport.model_validate(json.loads(path.read_text(encoding="utf-8"))))
        except (ValueError, json.JSONDecodeError) as exc:
            raise GoldError(f"{path.name}: {exc}") from exc
    return reports
