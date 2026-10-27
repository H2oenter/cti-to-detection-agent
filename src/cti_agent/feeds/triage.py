"""Decide which advisories deserve a pre-patch hunt. Code only, no model.

An advisory passes when it matches a product on the watchlist AND shows a remote code
execution signal: an RCE-class CWE, RCE wording, a KEV listing or SSVC "active".
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from cti_agent.models import VulnAdvisory

RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-434", "CWE-917", "CWE-1336"}
RCE_WORDING = re.compile(
    r"remote code execution|arbitrary code execution|execute arbitrary (?:code|commands)"
    r"|command injection|code injection|\bRCE\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class WatchedProduct:
    name: str
    vendors: tuple[str, ...]
    products: tuple[str, ...]
    packages: tuple[str, ...]
    processes: tuple[str, ...]
    servers: tuple[str, ...]
    tvm_names: tuple[str, ...]


@dataclass
class Triage:
    advisory: VulnAdvisory
    product: WatchedProduct | None
    signals: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.product is not None and bool(self.signals)


def load_watchlist(path: Path) -> list[WatchedProduct]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [
        WatchedProduct(
            name=p["name"],
            **{
                k: tuple(s.lower() for s in p.get(k, []))
                for k in ("vendors", "products", "packages", "processes", "servers", "tvm_names")
            },
        )
        for p in data.get("product", [])
    ]


def match_product(advisory: VulnAdvisory, watchlist: list[WatchedProduct]) -> WatchedProduct | None:
    for watched in watchlist:
        for affected in advisory.affected:
            vendor = (affected.vendor or "").lower()
            product = affected.product.lower()
            if vendor in watched.vendors or product in watched.products:
                return watched
            if affected.ecosystem:
                key = f"{affected.ecosystem.lower()}:{product}"
                if any(fnmatch.fnmatch(key, pattern) for pattern in watched.packages):
                    return watched
    return None


def rce_signals(advisory: VulnAdvisory) -> list[str]:
    signals = sorted(set(advisory.cwes) & RCE_CWES)
    text = f"{advisory.title or ''} {advisory.description}"
    if match := RCE_WORDING.search(text):
        signals.append(f'wording: "{match.group(0)}"')
    if advisory.kev_listed:
        signals.append("CISA KEV")
    if advisory.ssvc_exploitation == "active":
        signals.append("SSVC exploitation: active")
    return signals


def triage(advisory: VulnAdvisory, watchlist: list[WatchedProduct]) -> Triage:
    return Triage(advisory, match_product(advisory, watchlist), rce_signals(advisory))
