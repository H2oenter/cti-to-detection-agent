"""Decide which advisories deserve a pre-patch hunt, for any product. Code only, no model.

Each advisory gets a tier:
- hunt now:  exploited (CISA KEV, CISA's SSVC "active", the vendor saying so, or a public
             scanner template), unless it's known to be minor (CVSS under 7, no impact signal);
- hunt soon: not known to be exploited, but critical (CVSS 9+) with a serious impact:
             code execution, auth bypass, privilege escalation and the like;
- watch:     a serious impact or CVSS 7+, but neither of the above;
- other:     everything else.

The watchlist no longer filters: a product you run only ranks first within its tier.

`reasons` explains a tier. `signals` is the older remote-code-execution list, kept word for
word because the pre-patch analyst prompt quotes it and recorded runs are keyed on prompts.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from cti_agent.models import VulnAdvisory

TIERS = ("hunt now", "hunt soon", "watch", "other")
PASSING = {"hunt now", "hunt soon"}

RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-434", "CWE-917", "CWE-1336"}
IMPACT_CWES = {
    "code execution": RCE_CWES,
    "memory corruption": {"CWE-119", "CWE-121", "CWE-122", "CWE-416", "CWE-787", "CWE-843"},
    "auth bypass": {"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-302", "CWE-306",
                    "CWE-798", "CWE-862", "CWE-863"},
    "privilege escalation": {"CWE-250", "CWE-266", "CWE-268", "CWE-269", "CWE-274", "CWE-732"},
    "SQL injection": {"CWE-89"},
    "path traversal": {"CWE-22", "CWE-23", "CWE-35", "CWE-36"},
}  # fmt: skip
IMPACT_WORDING = {
    "code execution": re.compile(
        r"remote code execution|arbitrary code execution|execute arbitrary (?:code|commands)"
        r"|command injection|code injection|\bRCE\b",
        re.IGNORECASE,
    ),
    "auth bypass": re.compile(
        r"authentication bypass|bypass (?:the )?authentication|auth(?:entication)? bypass",
        re.IGNORECASE,
    ),
    "privilege escalation": re.compile(
        r"privilege escalation|elevation of privilege|escalate (?:their )?privileges"
        r"|gain (?:root|system|administrator|admin) (?:privileges|access)",
        re.IGNORECASE,
    ),
}
RCE_WORDING = IMPACT_WORDING["code execution"]
EXPLOITED_WORDING = re.compile(
    r"exploited in the wild|actively exploited|active exploitation|has been exploited"
    r"|(?:is|are) aware (?:of|that) [^.]{0,80}?exploit|limited,? targeted attacks?"
    r"|zero[- ]day(?! initiative)|\b0-day\b",
    re.IGNORECASE,
)
# "There is no evidence this has been exploited" is not a report of exploitation.
NEGATED = re.compile(
    r"\bno (?:evidence|known|reports?|indication)\b|\bnot (?:aware|known)\b|\bunaware\b",
    re.IGNORECASE,
)
# GitHub advisories often give a severity label and a vector but no numeric score.
SEVERITY_FLOOR = {"critical": 9.0, "high": 7.0, "moderate": 4.0, "medium": 4.0, "low": 0.1}
NO_FIX_WORDING = re.compile(
    r"no (?:patch|fix|update) is (?:currently )?available|not yet (?:been )?(?:patched|fixed)"
    r"|(?:patch|fix) is not yet available|will be (?:fixed|addressed) in a future",
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
    product: WatchedProduct | None  # a watchlist match ranks first; it no longer gates
    signals: list[str] = field(default_factory=list)  # the older RCE list; see the docstring
    exploited: list[str] = field(default_factory=list)
    impact: list[str] = field(default_factory=list)
    no_fix: bool = False
    tier: str = "other"

    @property
    def passed(self) -> bool:
        return self.tier in PASSING

    @property
    def zero_day(self) -> bool:
        """Exploited, and the advisory lists no fixed version yet."""
        return bool(self.exploited) and self.no_fix

    @property
    def reasons(self) -> list[str]:
        return self.exploited + self.impact + (["no fix listed"] if self.no_fix else [])

    def rank_key(self) -> tuple:
        return rank_key(self.tier, self.product is not None, self.zero_day,
                        score(self.advisory), self.advisory.id)  # fmt: skip


def rank_key(tier: str, watched: bool, zero_day: bool, cvss: float | None, advisory_id: str):
    """Tier first; then your own products, zero-days, and the higher score."""
    return (TIERS.index(tier), not watched, not zero_day, -(cvss or 0), advisory_id)


def score(advisory: VulnAdvisory) -> float | None:
    """The CVSS base score, or a floor for the severity label when there's no score."""
    if advisory.cvss_score is not None:
        return advisory.cvss_score
    return SEVERITY_FLOOR.get(advisory.severity or "")


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


def _text(advisory: VulnAdvisory) -> str:
    return f"{advisory.title or ''} {advisory.description}"


def rce_signals(advisory: VulnAdvisory) -> list[str]:
    """The pre-patch prompt's "exploitation signals" line; unchanged from the first version."""
    signals = sorted(set(advisory.cwes) & RCE_CWES)
    if match := RCE_WORDING.search(_text(advisory)):
        signals.append(f'wording: "{match.group(0)}"')
    if advisory.kev_listed:
        signals.append("CISA KEV")
    if advisory.ssvc_exploitation == "active":
        signals.append("SSVC exploitation: active")
    return signals


def exploited_signals(advisory: VulnAdvisory) -> list[str]:
    signals = []
    if advisory.kev_listed:
        signals.append("CISA KEV")
    if advisory.ssvc_exploitation == "active":
        signals.append("SSVC exploitation: active")
    for sentence in re.split(r"(?<=[.!?])\s+", _text(advisory)):
        match = EXPLOITED_WORDING.search(sentence)
        if match and not NEGATED.search(sentence):
            signals.append(f'wording: "{match.group(0)}"')
            break
    return signals


def impact_signals(advisory: VulnAdvisory) -> list[str]:
    found = {name for name, cwes in IMPACT_CWES.items() if set(advisory.cwes) & cwes}
    found |= {name for name, pattern in IMPACT_WORDING.items() if pattern.search(_text(advisory))}
    return [name for name in IMPACT_CWES if name in found]  # a stable order


def no_fix_listed(advisory: VulnAdvisory) -> bool:
    """Version data that names no fixed release, or the vendor saying no fix exists yet.
    A record with no version data at all (a bare KEV entry) says nothing either way."""
    ranges = [r for p in advisory.affected for r in p.ranges]
    if NO_FIX_WORDING.search(_text(advisory)):
        return True
    return bool(ranges) and not any(r.fixed for r in ranges)


def tier_for(exploited: list[str], impact: list[str], cvss: float | None) -> str:
    if exploited and (impact or cvss is None or cvss >= 7):
        return "hunt now"
    if impact and cvss is not None and cvss >= 9:
        return "hunt soon"
    if impact or exploited or (cvss is not None and cvss >= 7):
        return "watch"
    return "other"


def triage(
    advisory: VulnAdvisory,
    watchlist: list[WatchedProduct],
    extra_exploited: tuple[str, ...] = (),
) -> Triage:
    """`extra_exploited` carries signals found outside the record, such as a public
    scanner template for the CVE."""
    exploited = exploited_signals(advisory) + list(extra_exploited)
    impact = impact_signals(advisory)
    return Triage(
        advisory,
        match_product(advisory, watchlist),
        rce_signals(advisory),
        exploited,
        impact,
        no_fix_listed(advisory),
        tier_for(exploited, impact, score(advisory)),
    )


def ranked(results: list[Triage]) -> list[Triage]:
    return sorted(results, key=Triage.rank_key)
