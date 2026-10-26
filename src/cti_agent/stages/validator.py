"""Stage 2: deterministic checks on everything the collector returned. No LLM.

Order of checks for every item:
  1. shape  - is it a well-formed IP / domain / hash / CVE / technique ID?
  2. evidence - is the quote in the source, and is the value in its own quote?
  3. policy - private ranges, reserved names, the allowlist.

The second check is the main anti-hallucination control (design rule 4).
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from cti_agent.attack.attack_index import AttackLookup
from cti_agent.models import (
    AcceptedItem,
    ExtractedActor,
    ExtractedCVE,
    ExtractedIndicator,
    ExtractedItem,
    ExtractedTechnique,
    Extraction,
    ItemType,
    Rejection,
    RejectReason,
    ValidationResult,
)
from cti_agent.util.normalise import SourceIndex, item_hash, match_key, refang

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+)$")
URL_SCHEMES = {"http", "https", "ftp", "ftps"}

# RFC 2606 / 6761 names and common internal suffixes: never real IOCs.
RESERVED_TLDS = {"example", "invalid", "test", "localhost", "local", "internal", "lan", "home"}
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
# File extensions a model may mistake for a TLD. Real TLDs (.zip, .mov, .sh, .py) are not here.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "jse", "wsf", "hta",
    "lnk", "msi", "scr", "tmp", "dat", "log", "txt", "ini", "cfg", "conf", "json", "xml",
    "yaml", "yml", "csv", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf",
    "iso", "img", "vhd", "vhdx", "jar", "php", "asp", "aspx", "jsp", "jpg", "jpeg", "png",
    "gif", "rar", "gz", "tgz", "elf", "dmg", "apk",
}  # fmt: skip


class _Reject(Exception):
    def __init__(self, reason: RejectReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Allowlist:
    domains: frozenset[str]
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    @classmethod
    def load(cls, path: Path) -> Allowlist:
        domains: set[str] = set()
        networks = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip().lower()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                domains.add(entry.rstrip("."))
        return cls(frozenset(domains), tuple(networks))

    def has_domain(self, domain: str) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in self.domains)

    def has_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip in net for net in self.networks)


def validate(
    extractions: Iterable[Extraction],
    source: SourceIndex,
    attack: AttackLookup,
    allowlist: Allowlist,
) -> ValidationResult:
    v = _Validator(source, attack, allowlist)
    for extraction in extractions:
        for actor in extraction.actors:
            v.run("actor", actor)
        for cve in extraction.cves:
            v.run("cve", cve)
        for indicator in extraction.indicators:
            v.run("indicator", indicator)
        for technique in extraction.techniques:
            v.run("technique", technique)
    return v.result


def write_rejections(path: Path, rejected: list[Rejection]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for r in rejected:
            fh.write(json.dumps(r.model_dump(mode="json"), ensure_ascii=False) + "\n")


class _Validator:
    def __init__(self, source: SourceIndex, attack: AttackLookup, allowlist: Allowlist) -> None:
        self.source = source
        self.attack = attack
        self.allowlist = allowlist
        self.result = ValidationResult()
        self._accepted_keys: set[tuple[str, str]] = set()
        self._rejected_keys: set[tuple[str, str, str]] = set()

    def run(self, item_type: ItemType, item: ExtractedItem) -> None:
        key = (item_type, _dedupe_key(item))
        if key in self._accepted_keys:
            return  # same item from an overlapping chunk; first verified copy wins
        try:
            normalised, evidence_kind, page, warnings = self._check(item_type, item)
        except _Reject as rej:
            rkey = (*key, rej.reason)
            if rkey not in self._rejected_keys:
                self._rejected_keys.add(rkey)
                self.result.rejected.append(
                    Rejection(
                        item_type=item_type,
                        item=item.model_dump(mode="json"),
                        reason=rej.reason,
                        detail=rej.detail,
                    )
                )
            return
        self._accepted_keys.add(key)
        self.result.accepted.append(
            AcceptedItem(
                item_type=item_type,
                item=normalised,
                evidence_kind=evidence_kind,
                page=page,
                warnings=warnings,
                item_hash=item_hash(normalised),
            )
        )

    def _check(self, item_type: ItemType, item: ExtractedItem):
        if isinstance(item, ExtractedIndicator):
            return self._indicator(item)
        if isinstance(item, ExtractedTechnique):
            return self._technique(item)
        if isinstance(item, ExtractedActor):
            return self._actor(item)
        if isinstance(item, ExtractedCVE):
            return self._cve(item)
        raise TypeError(f"unexpected item type {item_type}")

    # --- evidence ---------------------------------------------------------------------

    def _quote_page(self, quote: str) -> int | None:
        match = self.source.find(quote)
        if not match.found:
            raise _Reject("quote_not_in_source", f"quote not found in source: {quote[:120]!r}")
        return match.page

    @staticmethod
    def _require_in_quote(value: str, quote: str) -> None:
        if value.lower() not in match_key(quote).lower():
            raise _Reject("value_not_in_quote", f"{value!r} does not appear in its own quote")

    # --- item types -------------------------------------------------------------------

    def _indicator(self, ind: ExtractedIndicator):
        value = _normalise_indicator(ind.kind, ind.value)
        page = self._quote_page(ind.evidence.quote)
        self._require_in_quote(value, ind.evidence.quote)
        self._policy(ind.kind, value)
        return ind.model_copy(update={"value": value}), "explicit", page, []

    def _technique(self, tech: ExtractedTechnique):
        attack_id = tech.attack_id.strip().upper()
        if not TECHNIQUE_RE.match(attack_id):
            raise _Reject("malformed", f"not an ATT&CK technique ID: {tech.attack_id!r}")
        info = self.attack.lookup(attack_id)
        if info is None:
            raise _Reject("unknown_technique", f"{attack_id} is not in the local ATT&CK bundle")
        page = self._quote_page(tech.evidence.quote)
        warnings = []
        if info.revoked:
            replacement = f"; replaced by {info.revoked_by}" if info.revoked_by else ""
            warnings.append(f"{attack_id} is revoked in ATT&CK{replacement}")
        if info.deprecated:
            warnings.append(f"{attack_id} is deprecated in ATT&CK")
        kind = "explicit" if attack_id in match_key(tech.evidence.quote).upper() else "inferred"
        return tech.model_copy(update={"attack_id": attack_id}), kind, page, warnings

    def _actor(self, actor: ExtractedActor):
        name = actor.name.strip()
        if not name:
            raise _Reject("malformed", "empty actor name")
        page = self._quote_page(actor.evidence.quote)
        self._require_in_quote(name, actor.evidence.quote)
        kept = [a.strip() for a in actor.aliases if a.strip() and self.source.contains(a)]
        dropped = [a for a in actor.aliases if a.strip() and a.strip() not in kept]
        warnings = [f"alias not found in source, dropped: {a!r}" for a in dropped]
        return actor.model_copy(update={"name": name, "aliases": kept}), "explicit", page, warnings

    def _cve(self, cve: ExtractedCVE):
        cve_id = cve.cve_id.strip().upper()
        if not CVE_RE.match(cve_id):
            raise _Reject("bad_cve", f"not a CVE ID: {cve.cve_id!r}")
        page = self._quote_page(cve.evidence.quote)
        self._require_in_quote(cve_id, cve.evidence.quote)
        return cve.model_copy(update={"cve_id": cve_id}), "explicit", page, []

    # --- policy -----------------------------------------------------------------------

    def _policy(self, kind: str, value: str) -> None:
        if kind in ("ipv4", "ipv6"):
            self._ip_policy(ipaddress.ip_address(value))
        elif kind == "domain":
            self._domain_policy(value)
        elif kind == "email":
            self._domain_policy(value.rsplit("@", 1)[1])
        elif kind == "url":
            host = urlsplit(value).hostname or ""
            try:
                self._ip_policy(ipaddress.ip_address(host))
            except ValueError:
                self._domain_policy(host)

    def _ip_policy(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if not ip.is_global or ip.is_multicast:
            raise _Reject("non_public_ip", f"{ip} is private, reserved or otherwise non-public")
        if self.allowlist.has_ip(ip):
            raise _Reject("allowlisted", f"{ip} is on the allowlist")

    def _domain_policy(self, domain: str) -> None:
        tld = domain.rsplit(".", 1)[-1]
        if tld in RESERVED_TLDS or any(
            domain == d or domain.endswith("." + d) for d in RESERVED_DOMAINS
        ):
            raise _Reject("reserved_domain", f"{domain} is a reserved or internal name")
        if self.allowlist.has_domain(domain):
            raise _Reject("allowlisted", f"{domain} is on the allowlist")


def _normalise_indicator(kind: str, raw: str) -> str:
    value = refang(raw.strip()).strip()
    if kind in HASH_LENGTHS:
        value = value.lower()
        if len(value) != HASH_LENGTHS[kind] or not _HEX.match(value):
            raise _Reject("bad_hash", f"{raw!r} is not a valid {kind}")
        return value
    if kind in ("ipv4", "ipv6"):
        value = value.strip("[]")
        if kind == "ipv4" and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", value):
            value = value.rsplit(":", 1)[0]
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise _Reject("malformed", f"{raw!r} is not an IP address") from None
        if (kind == "ipv4") != (ip.version == 4):
            raise _Reject("malformed", f"{raw!r} is not an {kind} address")
        return str(ip)
    if kind == "domain":
        return _normalise_domain(value, raw)
    if kind == "email":
        match = EMAIL_RE.match(value.lower())
        if not match:
            raise _Reject("malformed", f"{raw!r} is not an email address")
        _normalise_domain(match.group(1), raw)
        return value.lower()
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme.lower() not in URL_SCHEMES or not parts.hostname:
            raise _Reject("malformed", f"{raw!r} is not an http(s) or ftp URL")
        try:
            ipaddress.ip_address(parts.hostname)
        except ValueError:
            _normalise_domain(parts.hostname, raw)
        return value
    raise _Reject("malformed", f"unknown indicator kind {kind!r}")


def _normalise_domain(value: str, raw: str) -> str:
    domain = value.lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise _Reject("malformed", f"{raw!r} is not a valid domain") from None
    if not DOMAIN_RE.match(domain):
        raise _Reject("malformed", f"{raw!r} is not a valid domain")
    if domain.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
        raise _Reject("looks_like_filename", f"{raw!r} looks like a file name, not a domain")
    return domain


def _dedupe_key(item: ExtractedItem) -> str:
    if isinstance(item, ExtractedIndicator):
        return f"{item.kind}:{refang(item.value.strip()).lower()}"
    if isinstance(item, ExtractedTechnique):
        return item.attack_id.strip().upper()
    if isinstance(item, ExtractedActor):
        return item.name.strip().lower()
    return item.cve_id.strip().upper()
