"""Labelling help for gold files: deterministic, no model, no network.

Lists every technique ID and indicator-like string in a report, with page and context,
and cross-checks indicators against the publisher's own STIX file. The person labelling
decides; this only makes sure nothing in the text is overlooked. It never uses the
system under test, so the labels stay independent of it. When the labelling is done,
finish_draft() checks the draft the way the eval will read it and saves the gold file.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from cti_agent.evaluation.gold import GoldError, GoldReport
from cti_agent.evaluation.runner import EvalError, pinned_source
from cti_agent.inputs import SourceDoc
from cti_agent.stages.validator import normalise_value
from cti_agent.util.normalise import collapse_ws, fold, refang

_PATTERNS = [
    ("url", re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]+", re.IGNORECASE)),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")),
]
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_STIX_VALUE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url|email-addr):value\s*=\s*'((?:\\'|[^'])+)'"
)
_STIX_HASH = re.compile(
    r"file:hashes\.(?:'|\")?(SHA-256|SHA256|SHA-1|SHA1|MD5)(?:'|\")?\s*=\s*'([0-9a-fA-F]+)'",
    re.IGNORECASE,
)
_STIX_KINDS = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain",
               "url": "url", "email-addr": "email"}  # fmt: skip
_HASH_KINDS = {"SHA-256": "sha256", "SHA256": "sha256", "SHA-1": "sha1", "SHA1": "sha1",
               "MD5": "md5"}  # fmt: skip


@dataclass
class Candidate:
    kind: str
    value: str
    pages: list[int] = field(default_factory=list)
    context: str = ""
    in_stix: bool = False


def _context(text: str, start: int, end: int, radius: int = 90) -> str:
    return collapse_ws(text[max(0, start - radius) : end + radius])


def text_candidates(doc: SourceDoc) -> tuple[dict, dict, dict]:
    """(indicators, techniques, cves), each keyed so repeats across pages merge."""
    indicators: dict[tuple[str, str], Candidate] = {}
    techniques: dict[str, Candidate] = {}
    cves: dict[str, Candidate] = {}
    for number, page in enumerate(doc.pages, start=1):
        text = refang(fold(page))
        taken: list[tuple[int, int]] = []
        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                if any(s <= match.start() < e for s, e in taken):
                    continue  # part of a longer match, e.g. the domain inside a URL
                value = normalise_value(kind, match.group(0).rstrip(".,;:"))
                if value is None or (kind == "ipv4" and not _plausible_ip(value)):
                    continue
                taken.append(match.span())
                cand = indicators.setdefault(
                    (kind, value.lower()),
                    Candidate(kind, value, context=_context(text, *match.span())),
                )
                if number not in cand.pages:
                    cand.pages.append(number)
        for found, table in ((TECHNIQUE, techniques), (CVE, cves)):
            for match in found.finditer(text):
                cand = table.setdefault(
                    match.group(0),
                    Candidate("technique" if found is TECHNIQUE else "cve", match.group(0),
                              context=_context(text, *match.span())),
                )  # fmt: skip
                if number not in cand.pages:
                    cand.pages.append(number)
    return indicators, techniques, cves


def _plausible_ip(value: str) -> bool:
    # Version strings such as 1.2.3.4 look like IPs; keep only addresses that could be routed.
    return ipaddress.ip_address(value).is_global


def stix_indicators(path: Path) -> set[tuple[str, str]]:
    """Indicator values in a publisher's STIX 2.x JSON: patterns and observables."""
    data = json.loads(path.read_text(encoding="utf-8"))
    objects = data.get("objects", data if isinstance(data, list) else [])
    found: set[tuple[str, str]] = set()

    def add(kind: str, raw: str) -> None:
        if (value := normalise_value(kind, raw.replace("\\'", "'"))) is not None:
            found.add((kind, value.lower()))

    for obj in objects:
        kind = _STIX_KINDS.get(obj.get("type", ""))
        if kind and "value" in obj:
            add(kind, obj["value"])
        for algorithm, digest in (obj.get("hashes") or {}).items():
            if algorithm.upper() in _HASH_KINDS:
                add(_HASH_KINDS[algorithm.upper()], digest)
        pattern = obj.get("pattern", "")
        for stix_type, value in _STIX_VALUE.findall(pattern):
            add(_STIX_KINDS[stix_type], value)
        for algorithm, digest in _STIX_HASH.findall(pattern):
            add(_HASH_KINDS[algorithm.upper()], digest)
    return found


def draft(doc: SourceDoc, report_id: str, stix: Path | None = None) -> dict:
    indicators, techniques, cves = text_candidates(doc)
    in_stix = stix_indicators(stix) if stix else set()
    for key, cand in indicators.items():
        cand.in_stix = key in in_stix
    buckets = {
        "in_text_and_stix": [c for c in indicators.values() if c.in_stix],
        "text_only": [c for c in indicators.values() if not c.in_stix],
        "stix_only": [
            {"kind": k, "value": v,
             "reason": "only in the STIX file: the model reads the text, so it can't find it"}
            for k, v in sorted(in_stix - set(indicators))
        ],
    }  # fmt: skip
    seeded = buckets["in_text_and_stix"] if stix else []
    return {
        "report_id": report_id,
        "generated_by": "scripts/gold_draft.py (deterministic: no model, no network)",
        "how_to_use": (
            "Check every candidate against the report and eval/gold/README.md and edit "
            "'gold', then run: python scripts/gold_draft.py --finish <this file>. "
            "The eval never reads drafts."
        ),
        "indicator_candidates": {
            k: [asdict(c) if isinstance(c, Candidate) else c for c in v] for k, v in buckets.items()
        },
        "technique_candidates": [asdict(c) for c in techniques.values()],
        "cve_candidates": [asdict(c) for c in cves.values()],
        "gold": {
            "report_id": report_id,
            "title": "",
            "source": {"url": None, "file": doc.path.as_posix(), "sha256": doc.sha256},
            "labelled_by": "",
            "labelled_on": "",
            "indicators": [{"kind": c.kind, "value": c.value} for c in seeded],
            "optional_indicators": [],
            "techniques": list(techniques),
            "optional_techniques": [],
            "actors": [],
            "cves": list(cves),
            "notes": "",
        },
    }


# What a person must fill in before a draft can become a gold file.
REQUIRED_METADATA = ("title", "source.url", "labelled_by", "labelled_on", "actors")
_REPORT_ID = re.compile(r"[a-z0-9][a-z0-9._-]*")


@dataclass
class Finished:
    path: Path
    gold: GoldReport
    notes: list[str]  # things worth a second look; none of them stop the save


def finish_draft(draft_path: Path, out_dir: Path | None = None, *, force: bool = False) -> Finished:
    """Check a labelled draft the way the eval will read it, then save its gold section as
    <report_id>.json next to it. Raises GoldError, and writes nothing, if the metadata isn't
    filled in, the labels don't load, or the report has changed since it was labelled."""
    try:
        drafted = json.loads(draft_path.read_text(encoding="utf-8"))
        section = drafted["gold"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise GoldError(f"{draft_path}: not a draft from gold_draft.py ({exc!r})") from exc
    if blank := [name for name in REQUIRED_METADATA if not _filled(section, name)]:
        raise GoldError(f"{draft_path.name}: fill in {', '.join(blank)} first")
    try:
        date.fromisoformat(section["labelled_on"])
    except ValueError:
        raise GoldError(f"labelled_on should be a date like 2026-11-02, not "
                        f"{section['labelled_on']!r}") from None  # fmt: skip
    try:
        gold = GoldReport.model_validate(section)
    except ValueError as exc:
        raise GoldError(f"{draft_path.name}: {exc}") from exc
    if not _REPORT_ID.fullmatch(gold.report_id):
        raise GoldError(f"report_id {gold.report_id!r}: use lower-case letters, digits and -")
    try:
        pinned_source(gold)
    except EvalError as exc:
        raise GoldError(str(exc)) from exc

    path = (out_dir or draft_path.parent) / f"{gold.report_id}.json"
    if path.exists() and not force:
        raise GoldError(f"{path} already exists; pass --force to replace it")
    path.write_text(json.dumps(section, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return Finished(path, gold, _second_looks(drafted, section))


def _filled(section: dict, name: str) -> bool:
    value: object = section
    for part in name.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return bool(value.strip()) if isinstance(value, str) else bool(value)


def _second_looks(drafted: dict, section: dict) -> list[str]:
    """Parts of the labels still exactly as the helper pre-filled them. That can be right,
    but it's also what an unreviewed section looks like."""
    notes = []
    prefilled = [c["value"] for c in drafted.get("technique_candidates", [])]
    if section["techniques"] == prefilled and not section["optional_techniques"]:
        notes.append(
            f"techniques: all {len(prefilled)} IDs printed in the text are required, as the "
            "helper pre-filled them. Tool capabilities belong in optional_techniques."
        )
    candidates = drafted.get("indicator_candidates", {})
    text_only = candidates.get("text_only", [])
    seeded = [{"kind": c["kind"], "value": c["value"]}
              for c in candidates.get("in_text_and_stix", [])]  # fmt: skip
    if text_only and section["indicators"] == seeded and not section["optional_indicators"]:
        notes.append(
            f"indicators: none of the {len(text_only)} text-only candidates was added. "
            "Fine if they're all placeholders, contacts, tools or references."
        )
    return notes
