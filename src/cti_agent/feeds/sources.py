"""Read the three feeds and map their structured fields to VulnAdvisory. No LLM.

IDs, versions, CWEs, CVSS and exploitation status come from fields the publishers
structure, so no model is needed (or trusted) to read them. Free text (titles and
descriptions) is carried along as untrusted data for later stages.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime

from cti_agent.feeds.http import FeedError, Fetcher, build_url
from cti_agent.models import AffectedProduct, VersionRange, VulnAdvisory


@dataclass
class FeedItem:
    """One record as fetched (raw bytes kept for the inbox) and as mapped."""

    source: str
    raw: bytes
    url: str
    advisory: VulnAdvisory


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    value = re.sub(r"\.(\d{6})\d+", r".\1", value)  # OSV uses nanoseconds
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


# --- CISA KEV ---------------------------------------------------------------------------


def fetch_kev(fetcher: Fetcher, cfg: dict, since: datetime) -> list[FeedItem]:
    try:
        url = cfg["catalogue"]
        body = fetcher.get(url)
    except FeedError:
        url = cfg["mirror"]
        body = fetcher.get(url)
    items = []
    for vuln in json.loads(body)["vulnerabilities"]:
        added = date.fromisoformat(vuln["dateAdded"])
        if added >= since.date():
            raw = json.dumps(vuln, indent=1).encode("utf-8")
            items.append(FeedItem("kev", raw, url, map_kev(vuln)))
    return items


def map_kev(vuln: dict) -> VulnAdvisory:
    notes = vuln.get("notes", "")
    return VulnAdvisory(
        id=vuln["cveID"],
        source="kev",
        title=vuln.get("vulnerabilityName"),
        description=vuln.get("shortDescription", ""),
        affected=[AffectedProduct(vendor=vuln.get("vendorProject"), product=vuln["product"])],
        cwes=vuln.get("cwes", []),
        kev_listed=True,
        kev_due_date=date.fromisoformat(vuln["dueDate"]) if vuln.get("dueDate") else None,
        published=_ts(vuln.get("dateAdded")),
        references=re.findall(r"https?://[^\s;]+", notes),
    )


# --- OSV --------------------------------------------------------------------------------


def recent_osv_ids(
    fetcher: Fetcher, cfg: dict, ecosystem: str, since: datetime
) -> tuple[list[str], int]:
    """New or modified IDs, newest first. Returns (ids, malicious_package_count)."""
    url = build_url(cfg["index"], ecosystem=ecosystem)
    ids, malicious = [], 0
    lines = fetcher.lines(url)
    for row in csv.reader(lines):
        if len(row) != 2:
            continue
        modified = _ts(row[0])
        if modified is None or modified < since:
            break  # the file is sorted newest first
        if row[1].startswith("MAL-"):
            malicious += 1  # malicious packages: removal, not hunting
            continue
        ids.append(row[1])
        if len(ids) >= cfg["max_records"]:
            break
    lines.close()
    return ids, malicious


def fetch_osv(
    fetcher: Fetcher, cfg: dict, since: datetime, errors: list[str]
) -> tuple[list[FeedItem], int]:
    items, malicious_total = [], 0
    for ecosystem in cfg["ecosystems"]:
        try:
            ids, malicious = recent_osv_ids(fetcher, cfg, ecosystem, since)
        except FeedError as exc:  # one ecosystem's index failing doesn't cost the others
            errors.append(f"osv {ecosystem}: {exc}")
            continue
        malicious_total += malicious
        for osv_id in ids:
            try:
                url = build_url(cfg["record"], cfg["id_pattern"], ecosystem=ecosystem, id=osv_id)
                raw = fetcher.get(url)
                items.append(FeedItem("osv", raw, url, map_osv(json.loads(raw))))
            except (FeedError, ValueError, KeyError) as exc:
                errors.append(f"osv {osv_id}: {exc}")
    return items, malicious_total


def map_osv(record: dict) -> VulnAdvisory:
    affected = []
    for entry in record.get("affected", []):
        package = entry.get("package", {})
        ranges = []
        for rng in entry.get("ranges", []):
            current = VersionRange()
            for event in rng.get("events", []):
                if "introduced" in event:
                    current = VersionRange(introduced=event["introduced"])
                for key in ("fixed", "last_affected"):
                    if key in event:
                        ranges.append(current.model_copy(update={key: event[key]}))
                        current = VersionRange()
            if current.introduced:
                ranges.append(current)
        affected.append(
            AffectedProduct(
                ecosystem=package.get("ecosystem"),
                product=package.get("name", "unknown"),
                ranges=ranges,
                versions=entry.get("versions", [])[:50],
            )
        )
    severity = next((s["score"] for s in record.get("severity", []) if "score" in s), None)
    fixed = any(r.fixed for a in affected for r in a.ranges)
    label = str(record.get("database_specific", {}).get("severity") or "").lower()
    return VulnAdvisory(
        id=record["id"],
        aliases=record.get("aliases", []),
        source="osv",
        title=record.get("summary"),
        description=record.get("details") or record.get("summary", ""),
        affected=affected,
        patch_available=True if fixed else None,
        cwes=record.get("database_specific", {}).get("cwe_ids", []),
        cvss_vector=severity,
        severity=label if label in ("low", "moderate", "medium", "high", "critical") else None,
        published=_ts(record.get("published")),
        modified=_ts(record.get("modified")),
        references=[r["url"] for r in record.get("references", []) if "url" in r],
    )


# --- CVE List V5 ------------------------------------------------------------------------


def recent_cve_ids(fetcher: Fetcher, cfg: dict, since: datetime) -> list[str]:
    """CVE IDs new or updated since `since`, read from the head of deltaLog.json."""
    text = fetcher.get(cfg["delta_log"], range_bytes=cfg["delta_log_max_bytes"]).decode(
        "utf-8", errors="replace"
    )
    decoder = json.JSONDecoder()
    pos = text.index("[") + 1
    ids: list[str] = []
    while True:
        while pos < len(text) and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(text) or text[pos] == "]":
            break
        try:
            entry, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break  # the ranged read cut the last entry; everything before it is complete
        fetched = _ts(entry.get("fetchTime"))
        if fetched is None or fetched < since:
            break  # newest first
        for change in entry.get("new", []) + entry.get("updated", []):
            cve_id = change.get("cveId")
            if cve_id and cve_id not in ids:
                ids.append(cve_id)
    return ids[: cfg["max_records"]]


def cve_record_url(cfg: dict, cve_id: str) -> str:
    match = re.match(cfg["id_pattern"], cve_id)
    if not match:
        raise FeedError(f"not a CVE ID: {cve_id!r}")
    _, year, number = cve_id.split("-")
    return build_url(
        cfg["record"], cfg["id_pattern"], year=year, bucket=str(int(number) // 1000), id=cve_id
    )


def fetch_cves(
    fetcher: Fetcher, cfg: dict, cve_ids: list[str], errors: list[str]
) -> list[FeedItem]:
    items = []
    for cve_id in cve_ids:
        try:
            url = cve_record_url(cfg, cve_id)
            raw = fetcher.get(url)
            advisory = map_cve(json.loads(raw))
        except (FeedError, ValueError, KeyError) as exc:
            errors.append(f"cve {cve_id}: {exc}")
            continue
        if advisory is not None:  # REJECTED or RESERVED records are skipped
            items.append(FeedItem("cve", raw, url, advisory))
    return items


def map_cve(record: dict) -> VulnAdvisory | None:
    meta = record["cveMetadata"]
    if meta.get("state") != "PUBLISHED":
        return None
    cna = record["containers"]["cna"]
    adps = record["containers"].get("adp", [])
    description = next(
        (d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")),
        "",
    )
    affected, fixed = [], False
    for entry in cna.get("affected", []):
        ranges = []
        for v in entry.get("versions", []):
            if v.get("status") != "affected":
                continue
            upper = v.get("lessThan")
            wildcard = bool(upper) and "*" in upper  # "lessThan: 4.*" means every 4.x
            fixed = fixed or (bool(upper) and not wildcard)
            introduced = (v.get("version") or "").replace("*", "0") or None
            ranges.append(
                VersionRange(
                    introduced=introduced if introduced not in ("0", "n/a") else None,
                    fixed=None if wildcard else upper,
                    last_affected=upper if wildcard else v.get("lessThanOrEqual"),
                )
            )
        affected.append(
            AffectedProduct(
                vendor=entry.get("vendor"),
                product=entry.get("product") or entry.get("packageName") or "unknown",
                ecosystem=_ecosystem(entry.get("collectionURL")),
                ranges=ranges,
                platforms=entry.get("platforms", []),
                modules=entry.get("modules", []),
            )
        )
    cwes = sorted(
        {
            d["cweId"]
            for container in [cna, *adps]
            for p in container.get("problemTypes", [])
            for d in p.get("descriptions", [])
            if d.get("cweId")
        }
    )
    score, vector = _cvss(cna, adps)
    ssvc, kev = None, False
    for adp in adps:
        for metric in adp.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                for option in other.get("content", {}).get("options", []):
                    if "Exploitation" in option:
                        ssvc = option["Exploitation"].lower()
            if other.get("type") == "kev":
                kev = True
    return VulnAdvisory(
        id=meta["cveId"],
        source="cve",
        title=cna.get("title"),
        description=description,
        affected=affected,
        patch_available=True if fixed else None,
        cwes=cwes,
        cvss_score=score,
        cvss_vector=vector,
        kev_listed=kev,
        ssvc_exploitation=ssvc if ssvc in ("none", "poc", "active") else None,
        published=_ts(meta.get("datePublished")),
        modified=_ts(meta.get("dateUpdated")),
        references=[r["url"] for r in cna.get("references", []) if "url" in r],
    )


_ECOSYSTEMS = {"npmjs": "npm", "packagist": "Packagist", "pypi": "PyPI", "rubygems": "RubyGems"}


def _ecosystem(collection_url: str | None) -> str | None:
    """CVE 5 names a package ecosystem through its registry URL."""
    if not collection_url:
        return None
    return next((eco for key, eco in _ECOSYSTEMS.items() if key in collection_url.lower()), None)


def _cvss(cna: dict, adps: list[dict]) -> tuple[float | None, str | None]:
    for container in [cna, *adps]:
        for metric in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if key in metric:
                    return metric[key].get("baseScore"), metric[key].get("vectorString")
    return None, None


# --- Merging ----------------------------------------------------------------------------


def merge(items: list[FeedItem]) -> list[tuple[VulnAdvisory, list[FeedItem]]]:
    """One advisory per vulnerability: records that share a CVE ID are combined."""
    groups: dict[str, list[FeedItem]] = {}
    for item in items:
        adv = item.advisory
        cve = next((a for a in [adv.id, *adv.aliases] if a.startswith("CVE-")), adv.id)
        groups.setdefault(cve, []).append(item)
    merged = []
    for key, group in groups.items():
        # The CVE record is the richest; fall back to OSV, then KEV.
        order = {"cve": 0, "osv": 1, "kev": 2}
        group.sort(key=lambda i: order[i.source])
        base = group[0].advisory
        others = [i.advisory for i in group[1:]]
        aliases = sorted({a for adv in group for a in [adv.advisory.id, *adv.advisory.aliases]}
                         - {key})  # fmt: skip
        merged.append(
            (
                base.model_copy(
                    update={
                        "id": key,
                        "aliases": aliases,
                        "affected": base.affected + [p for o in others for p in o.affected],
                        "cwes": sorted({c for a in [base, *others] for c in a.cwes}),
                        "kev_listed": any(a.kev_listed for a in [base, *others]),
                        "kev_due_date": next(
                            (a.kev_due_date for a in [base, *others] if a.kev_due_date), None
                        ),
                        "description": base.description
                        or next((o.description for o in others if o.description), ""),
                    }
                ),
                group,
            )
        )
    return merged
