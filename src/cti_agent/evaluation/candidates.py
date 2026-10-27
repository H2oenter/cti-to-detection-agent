"""Labelling help for gold files: deterministic, no model, no network.

Lists every technique ID and indicator-like string in a report, with page and context,
and cross-checks indicators against the publisher's own STIX file. The person labelling
decides; this only makes sure nothing in the text is overlooked. It never uses the
system under test, so the labels stay independent of it.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

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
            "Check every candidate against the report and eval/gold/README.md, then edit "
            "'gold' and save it as eval/gold/<report_id>.json. The eval never reads drafts."
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
