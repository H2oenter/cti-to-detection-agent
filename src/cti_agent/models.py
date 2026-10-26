"""Data contracts for every stage.

Two families live here:

* What the collector model is asked to return (``Extraction`` and its parts).
  Field descriptions become the JSON schema the model sees, so they double as
  instructions.
* What the pipeline produces after deterministic checks (``AcceptedItem``,
  ``Rejection``, ``Provenance``, ``RunSummary``) plus ``VulnAdvisory`` for the
  feed track.

The evidence and provenance fields are the point of the design: nothing leaves
the validator without a quote that was found in the source.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field

TLP = Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]
IndicatorKind = Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"]
ItemType = Literal["indicator", "technique", "actor", "cve"]
EvidenceKind = Literal["explicit", "inferred"]

RejectReason = Literal[
    "quote_not_in_source",
    "value_not_in_quote",
    "suspected_injection",
    "malformed",
    "non_public_ip",
    "allowlisted",
    "reserved_domain",
    "looks_like_filename",
    "bad_hash",
    "bad_cve",
    "unknown_technique",
]


# --- What the collector model returns -------------------------------------------------


class Evidence(BaseModel):
    quote: str = Field(
        description="Exact text copied from the report that states this item. Copy it "
        "character for character, including defanged forms like hxxp or [.]. Keep it short: "
        "one sentence or one table row."
    )
    location: str | None = Field(
        default=None, description="Page or section heading if visible in the text, else null."
    )


class ExtractedIndicator(BaseModel):
    kind: IndicatorKind
    value: str = Field(description="The indicator, refanged (hxxp -> http, [.] -> .).")
    context: str = Field(description="One line: what the report says this indicator is.")
    evidence: Evidence


class ExtractedTechnique(BaseModel):
    attack_id: str = Field(description="MITRE ATT&CK technique ID, e.g. T1621 or T1566.004.")
    behaviour: str = Field(description="What the actor did, in the report's own terms.")
    evidence: Evidence


class ExtractedActor(BaseModel):
    name: str = Field(description="Actor or group name exactly as written in the report.")
    aliases: list[str] = Field(
        default_factory=list, description="Other names the report itself gives for this actor."
    )
    evidence: Evidence


class ExtractedCVE(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2023-4966.")
    context: str = Field(description="One line: what the report says about this CVE.")
    evidence: Evidence


class Extraction(BaseModel):
    report_title: str
    actors: list[ExtractedActor]
    cves: list[ExtractedCVE]
    indicators: list[ExtractedIndicator]
    techniques: list[ExtractedTechnique]


ExtractedItem = ExtractedIndicator | ExtractedTechnique | ExtractedActor | ExtractedCVE


# --- What the pipeline produces ------------------------------------------------------


class Provenance(BaseModel):
    source_file: str
    source_sha256: str
    source_kind: Literal["file", "feed"] = "file"
    source_name: str | None = None  # feed name, e.g. "osv"
    fetched_from: str | None = None  # feed endpoint the item came from
    fetched_at: datetime | None = None
    tlp: TLP = "CLEAR"
    ingested_at: datetime
    run_id: str
    prompt_version: str
    model: str


class Confidence(BaseModel):
    score: int = Field(ge=0, le=100)
    rationale: str


class AcceptedItem(BaseModel):
    item_type: ItemType
    item: ExtractedItem
    evidence_kind: EvidenceKind  # explicit: the value/ID is in the quote; inferred: it isn't
    page: int | None = None  # computed by the validator from where the quote matched
    warnings: list[str] = Field(default_factory=list)
    item_hash: str


class Rejection(BaseModel):
    item_type: ItemType
    item: dict
    reason: RejectReason
    detail: str


class ValidationResult(BaseModel):
    accepted: list[AcceptedItem] = Field(default_factory=list)
    rejected: list[Rejection] = Field(default_factory=list)

    def accepted_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.accepted:
            counts[a.item_type] = counts.get(a.item_type, 0) + 1
        return counts

    def rejected_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.rejected:
            counts[r.reason] = counts.get(r.reason, 0) + 1
        return counts


class RunSummary(BaseModel):
    run_id: str
    source_file: str
    status: Literal["complete", "partial", "failed"]
    stop_reason: str | None = None  # e.g. "budget", "refusal" when status is partial
    chunks_total: int
    chunks_done: int
    chunks_refused: int = 0
    accepted_counts: dict[str, int]
    rejected_counts: dict[str, int]
    input_tokens: int
    output_tokens: int
    est_cost_usd: float


# --- Feed track (M2) -----------------------------------------------------------------


class VersionRange(BaseModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class AffectedProduct(BaseModel):
    ecosystem: str | None = None  # npm, Packagist, ... or None for vendor products
    vendor: str | None = None
    product: str
    ranges: list[VersionRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)


class VulnAdvisory(BaseModel):
    """A vulnerability record mapped from a feed's structured fields, not by a model."""

    id: str
    aliases: list[str] = Field(default_factory=list)
    source: Literal["osv", "kev", "cve"]
    title: str | None = None
    description: str
    affected: list[AffectedProduct] = Field(default_factory=list)
    patch_available: bool | None = None
    cwes: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    kev_listed: bool = False
    kev_due_date: date | None = None
    ssvc_exploitation: Literal["none", "poc", "active"] | None = None
    published: datetime | None = None
    modified: datetime | None = None
    references: list[str] = Field(default_factory=list)  # recorded, never fetched
