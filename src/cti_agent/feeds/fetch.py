"""`cti-agent fetch`: pull, merge, triage and file fresh advisories. No model is involved.

Everything lands in reports/inbox/<date>/: each raw record with its SHA-256, an
advisories.json index with the triage result, and the list of URLs requested. From
there an advisory is untrusted input like any report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cti_agent.config import Settings
from cti_agent.feeds.http import FeedError, Fetcher, load_sources
from cti_agent.feeds.sources import (
    FeedItem,
    fetch_cves,
    fetch_kev,
    fetch_osv,
    merge,
    recent_cve_ids,
)
from cti_agent.feeds.triage import Triage, load_watchlist, triage
from cti_agent.util.normalise import sha256_bytes

SOURCES = ("kev", "osv", "cve")


@dataclass
class FetchResult:
    inbox: Path
    triaged: list[Triage]
    malicious_packages: int = 0
    requested: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def run_fetch(
    settings: Settings,
    *,
    since: timedelta,
    sources: tuple[str, ...] = SOURCES,
    cve_ids: tuple[str, ...] = (),
    opener=None,
    now: datetime | None = None,
) -> FetchResult:
    now = now or datetime.now(UTC)
    cutoff = now - since
    cfg = load_sources(settings.sources_file)
    fetcher = Fetcher.from_sources(cfg, opener=opener)
    items: list[FeedItem] = []
    errors: list[str] = []
    notes: list[str] = []
    malicious = 0
    ids = list(cve_ids)

    if "kev" in sources:
        try:
            kev_items = fetch_kev(fetcher, cfg["kev"], cutoff)
            items += kev_items
            # KEV entries carry no version data; their CVE records do, and merge in below.
            ids += [i.advisory.id for i in kev_items if i.advisory.id not in ids]
        except FeedError as exc:
            errors.append(f"kev: {exc}")
    if "osv" in sources:
        try:
            osv_items, malicious = fetch_osv(fetcher, cfg["osv"], cutoff, errors)
            items += osv_items
        except FeedError as exc:
            errors.append(f"osv: {exc}")
    if "cve" in sources:
        try:
            recent = recent_cve_ids(fetcher, cfg["cvelist"], cutoff)
            if len(recent) >= cfg["cvelist"]["max_records"]:
                notes.append(
                    f"the CVE delta hit its cap of {cfg['cvelist']['max_records']} records; "
                    "use a shorter --since or raise max_records in data/sources.toml"
                )
            ids += [i for i in recent if i not in ids]
        except FeedError as exc:
            errors.append(f"cvelist: {exc}")
    if ids:
        items += fetch_cves(fetcher, cfg["cvelist"], ids, errors)

    watchlist = load_watchlist(settings.watchlist_file)
    merged = merge(items)
    triaged = [triage(advisory, watchlist) for advisory, _ in merged]

    inbox = settings.inbox_dir / now.strftime("%Y%m%d")
    index = _load_index(inbox / "advisories.json")
    for (advisory, group), result in zip(merged, triaged, strict=True):
        records = []
        for item in group:
            path = inbox / item.source / f"{_safe(item.advisory.id)}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(item.raw)
            records.append(
                {
                    "source": item.source,
                    "url": item.url,
                    "path": path.relative_to(inbox).as_posix(),
                    "sha256": sha256_bytes(item.raw),
                }
            )
        index[advisory.id] = {
            "advisory": advisory.model_dump(mode="json"),
            "triage": {
                "passed": result.passed,
                "product": result.product.name if result.product else None,
                "signals": result.signals,
            },
            "records": records,
            "fetched_at": now.isoformat(timespec="seconds"),
        }
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / "advisories.json").write_text(
        json.dumps(index, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    with (inbox / "requests.log").open("a", encoding="utf-8") as log:
        for url in fetcher.requested:
            log.write(f"{now.isoformat(timespec='seconds')} GET {url}\n")
    return FetchResult(inbox, triaged, malicious, fetcher.requested, errors, notes)


def find_advisory(inbox_root: Path, advisory_id: str) -> tuple[dict, Path] | None:
    """The newest inbox entry for an advisory ID or alias, and the inbox it's in."""
    for day in sorted((p for p in inbox_root.glob("*") if p.is_dir()), reverse=True):
        index = _load_index(day / "advisories.json")
        for key, entry in index.items():
            if advisory_id == key or advisory_id in entry["advisory"].get("aliases", []):
                return entry, day
    return None


def parse_since(text: str) -> timedelta:
    units = {"m": "minutes", "h": "hours", "d": "days"}
    if len(text) < 2 or text[-1] not in units or not text[:-1].isdigit():
        raise ValueError(f"use a number and a unit, like 24h, 7d or 90m: {text!r}")
    return timedelta(**{units[text[-1]]: int(text[:-1])})


def _load_index(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _safe(identifier: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in identifier)
