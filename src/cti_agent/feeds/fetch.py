"""`cti-agent fetch`: pull, merge, triage and file fresh advisories. No model is involved.

Everything lands in reports/inbox/<date>/: each raw record with its SHA-256, an
advisories.json index with the triage result, and the list of URLs requested. From
there an advisory is untrusted input like any report.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cti_agent.config import Settings
from cti_agent.feeds.http import FeedError, Fetcher, build_url, load_sources
from cti_agent.feeds.sources import (
    FeedItem,
    fetch_cves,
    fetch_kev,
    fetch_osv,
    merge,
    recent_cve_ids,
)
from cti_agent.feeds.triage import Triage, load_watchlist, rank_key, ranked, score, triage
from cti_agent.models import VulnAdvisory
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
    templates = probe_templates(fetcher, cfg.get("nuclei"), triaged, errors)
    triaged = [
        triage(t.advisory, watchlist, templates[t.advisory.id]) if t.advisory.id in templates else t
        for t in triaged
    ]
    rank = {t.advisory.id: n for n, t in enumerate(ranked(triaged), start=1)}

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
                "tier": result.tier,
                "rank": rank[advisory.id],
                "zero_day": result.zero_day,
                "product": result.product.name if result.product else None,
                "exploited": result.exploited,
                "impact": result.impact,
                "reasons": result.reasons,
                "signals": result.signals,  # the older RCE list, quoted by the pre-patch prompt
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
    return FetchResult(inbox, ranked(triaged), malicious, fetcher.requested, errors, notes)


def probe_templates(
    fetcher: Fetcher, cfg: dict | None, triaged: list[Triage], errors: list[str]
) -> dict[str, tuple[str, ...]]:
    """Look for a public Nuclei template for the top-ranked CVEs that aren't already known to
    be exploited, where finding one changes the tier. Returns {advisory ID: extra signals}."""
    if not cfg:
        return {}
    pattern = re.compile(cfg["id_pattern"])
    candidates = [t for t in ranked(triaged) if t.tier in ("hunt soon", "watch")]
    found: dict[str, tuple[str, ...]] = {}
    for result in candidates[: cfg.get("check_top", 20)]:
        adv = result.advisory
        cve = next((i for i in (adv.id, *adv.aliases) if pattern.match(i)), None)
        if cve is None:
            continue
        try:
            for template in cfg["templates"]:
                url = build_url(template, cfg["id_pattern"], id=cve, year=cve.split("-")[1])
                if fetcher.exists(url):
                    found[adv.id] = ("public Nuclei template",)
                    break
        except FeedError as exc:
            errors.append(f"nuclei: {exc}")
    return found


def find_advisory(inbox_root: Path, advisory_id: str) -> tuple[dict, Path] | None:
    """The newest inbox entry for an advisory ID or alias, and the inbox it's in."""
    for day in sorted((p for p in inbox_root.glob("*") if p.is_dir()), reverse=True):
        index = _load_index(day / "advisories.json")
        for key, entry in index.items():
            if advisory_id == key or advisory_id in entry["advisory"].get("aliases", []):
                return entry, day
    return None


def top_candidates(inbox_root: Path, n: int) -> list[str]:
    """The n highest-ranked advisories in the newest inbox that passed triage. Ranked again
    here, because one inbox can hold several fetches."""
    days = sorted((p for p in inbox_root.glob("*") if p.is_dir()), reverse=True)
    if not days:
        return []
    index = _load_index(days[0] / "advisories.json")

    def key(item: tuple[str, dict]) -> tuple:
        advisory_id, entry = item
        t = entry["triage"]
        cvss = score(VulnAdvisory.model_validate(entry["advisory"]))
        return rank_key(t.get("tier", "other"), t["product"] is not None,
                        bool(t.get("zero_day")), cvss, advisory_id)  # fmt: skip

    passed = [item for item in index.items() if item[1]["triage"]["passed"]]
    return [advisory_id for advisory_id, _ in sorted(passed, key=key)[:n]]


def parse_since(text: str) -> timedelta:
    units = {"m": "minutes", "h": "hours", "d": "days"}
    if len(text) < 2 or text[-1] not in units or not text[:-1].isdigit():
        raise ValueError(f"use a number and a unit, like 24h, 7d or 90m: {text!r}")
    return timedelta(**{units[text[-1]]: int(text[:-1])})


def _load_index(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _safe(identifier: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in identifier)
