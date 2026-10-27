"""Pre-patch hunts for one triaged advisory: exposure queries and a behaviour hunt.

Exposure queries are written by code: the facts they need (product, affected and fixed
versions) are structured fields in the feed, so a model adds nothing but risk. The
behaviour hunt needs judgement, so the analyst model drafts it from observables pulled
out of the advisory text, each verified against that text, and the reviewer scores it.

A product on the watchlist comes with known process and inventory names. Any other product
is hunted by its vendor and product name from the advisory, matched approximately, and gets
a behaviour hunt only if the advisory gives something verifiable to look for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from cti_agent.attack.attack_index import AttackLookup
from cti_agent.feeds.triage import WatchedProduct
from cti_agent.models import (
    Confidence,
    CoverageEntry,
    Hunt,
    HuntDraft,
    Observable,
    PrepatchExtraction,
    VulnAdvisory,
)
from cti_agent.stages.validator import injection_hit, verify_quote
from cti_agent.util.kql_lint import KqlSchema, lint_kql
from cti_agent.util.normalise import SourceIndex, item_hash

_NUMERIC = re.compile(r"^\d+(?:\.\d+){0,3}$")
_SAFE_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,79}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
DEFAULT_TECHNIQUE = "T1190"  # Exploit Public-Facing Application
RETIRE_AFTER = timedelta(days=30)


def kql_value(value: str | None) -> str | None:
    """A feed value that is safe inside a KQL string: letters, digits, spaces and . _ + -,
    at most 80 characters, and not worded like an instruction. Anything else is refused, so
    text from a feed can never close the string and become query code."""
    value = " ".join((value or "").split())
    if not _SAFE_VALUE.fullmatch(value) or injection_hit(value):
        return None
    return value


def technique_from_vector(vector: str | None) -> str:
    """The default technique when the advisory names none, from the CVSS vector: user
    interaction means client-side exploitation, local access means privilege escalation,
    and anything else is a public-facing application."""
    parts = dict(p.split(":", 1) for p in (vector or "").split("/") if ":" in p)
    if parts.get("UI") in ("R", "P", "A"):  # CVSS 3 "required"; CVSS 4 "passive"/"active"
        return "T1203"
    if parts.get("AV") in ("L", "P"):
        return "T1068"
    return DEFAULT_TECHNIQUE


def cve_id(advisory: VulnAdvisory) -> str | None:
    return next((i for i in (advisory.id, *advisory.aliases) if _CVE.fullmatch(i)), None)


@dataclass(frozen=True)
class Target:
    """What a pre-patch hunt looks for: a watchlist product, or else the vendor and the
    products the advisory names for that vendor, made safe for a query."""

    name: str
    vendor: str | None = None
    products: tuple[str, ...] = ()
    tvm_names: tuple[str, ...] = ()
    watched: WatchedProduct | None = None

    @property
    def product(self) -> str | None:
        return self.products[0] if self.products else None


def software_names(product: str) -> tuple[str, ...]:
    """Defender's software names are lower case with underscores ("connect_secure")."""
    return tuple(dict.fromkeys((product.lower().replace(" ", "_"), product.lower())))


def target_for(advisory: VulnAdvisory, watched: WatchedProduct | None) -> Target:
    if watched:
        return Target(watched.name, tvm_names=watched.tvm_names, watched=watched)
    vendor, products = None, []
    for affected in advisory.affected:
        product = kql_value(affected.product)
        this_vendor = kql_value(affected.vendor or affected.ecosystem)
        if not product or (products and (this_vendor or "").lower() != (vendor or "").lower()):
            continue  # one vendor per target: the first one named
        vendor = vendor or this_vendor
        if product not in products:
            products.append(product)
    if not products:
        return Target(advisory.id)
    listed = ", ".join(products)
    name = listed if not vendor or vendor.lower() in listed.lower() else f"{vendor} {listed}"
    names = tuple(n for p in products for n in software_names(p))
    return Target(name, vendor, tuple(products), names)


def range_conditions(ranges) -> list[str]:
    """KQL conditions on a parsed `Version`, one per numeric range: below a fixed version,
    or up to and including the last affected one ("7.4.0 through 7.4.2")."""
    conditions = []
    for r in ranges:
        lower = (
            f'Version >= parse_version("{r.introduced}") and '
            if r.introduced and _NUMERIC.match(r.introduced)
            else ""
        )
        if r.fixed and _NUMERIC.match(r.fixed):
            conditions.append(f'({lower}Version < parse_version("{r.fixed}"))')
        elif not r.fixed and r.last_affected and _NUMERIC.match(r.last_affected):
            conditions.append(f'({lower}Version <= parse_version("{r.last_affected}"))')
    return sorted(set(conditions))


def version_conditions(advisory: VulnAdvisory) -> list[str]:
    return range_conditions(r for p in advisory.affected for r in p.ranges)


def advisory_text(advisory: VulnAdvisory) -> str:
    return f"{advisory.title or advisory.id}\n\n{advisory.description}".strip()


def first_sentence(text: str) -> str:
    match = re.match(r"(.+?[.!?])(\s|$)", " ".join(text.split()))
    return match.group(1) if match else " ".join(text.split())[:200]


def fixed_versions(advisory: VulnAdvisory) -> list[str]:
    return sorted({r.fixed for p in advisory.affected for r in p.ranges if r.fixed})


def verify_observables(
    extraction: PrepatchExtraction, source: SourceIndex
) -> tuple[list[Observable], list[str]]:
    kept, rejected = [], []
    for obs in extraction.observables:
        reason = verify_quote(source, obs.evidence.quote)
        if reason:
            rejected.append(f"{reason}: {obs.description}")
        else:
            kept.append(obs)
    return kept, rejected


def choose_technique(
    extraction: PrepatchExtraction | None,
    source: SourceIndex,
    attack: AttackLookup,
    default: str = DEFAULT_TECHNIQUE,
) -> CoverageEntry:
    """The first verified initial-access or execution technique the text names, else
    `default` (from the CVSS vector), else T1190."""
    candidates = []
    if extraction:
        for tech in extraction.techniques:
            info = attack.lookup(tech.attack_id)
            if info and not verify_quote(source, tech.evidence.quote):
                candidates.append(info)
    preferred = [i for i in candidates if {"initial-access", "execution"} & set(i.tactics)]
    fallback = attack.lookup(default) or attack.lookup(DEFAULT_TECHNIQUE)
    info = (preferred or candidates or [fallback])[0]
    return CoverageEntry(
        attack_id=info.attack_id,
        name=info.name,
        domain=info.domain,
        tactics=list(info.tactics),
        state="gap",
        evidence_kind="explicit",
    )


def retire_when(
    advisory: VulnAdvisory, product: str, now: datetime, *, names_approximate: bool = False
) -> str:
    """When the hunts can go. If product names were only matched approximately, an empty
    exposure result proves nothing, so it isn't offered as the sign."""
    fixed = fixed_versions(advisory)
    if names_approximate:
        patched = (
            f"a fixed {product} release ({', '.join(fixed) or 'see the vendor'}) is deployed "
            "everywhere; confirm it from your patch tooling, because an empty exposure result "
            "can also mean the names didn't match"
        )
    elif fixed:
        patched = (
            f"{product} is at {', '.join(fixed)} or later everywhere (the exposure query returns "
            "nothing)"
        )
    else:
        patched = f"a fixed {product} release is deployed everywhere"
    return f"Retire when {patched}, or on {(now + RETIRE_AFTER):%Y-%m-%d}, whichever is first."


def _kql_list(values: tuple[str, ...] | list[str]) -> str:
    return ", ".join(f'"{v}"' for v in values if kql_value(v) == v)


def exposure_query(advisory: VulnAdvisory, watched: WatchedProduct) -> tuple[str, list[str]]:
    """Returns (query, assumptions). Inventory only: it says nothing about exploitation."""
    assumptions = [
        f"Defender TVM lists the software with SoftwareName matching {list(watched.tvm_names)}; "
        "check the exact name in your tenant.",
    ]
    conditions = version_conditions(advisory)
    if any(p.ecosystem for p in advisory.affected):
        assumptions.append(
            "Defender doesn't inventory npm or Composer dependencies: this finds hosts running "
            f"{watched.name}; check SBOMs or lock files for the affected package itself."
        )
    by_version = (
        "DeviceTvmSoftwareInventory\n"
        f"    | where SoftwareName has_any ({_kql_list(watched.tvm_names)})\n"
        "    | extend Version = parse_version(SoftwareVersion)\n"
        + (f"    | where {' or '.join(conditions)}\n" if conditions else "")
        + '    | project DeviceName, SoftwareName, SoftwareVersion, Basis = "version range"'
    )
    if not conditions:
        assumptions.append("The advisory gives no numeric version range: every install is listed.")
    query = (
        f"// Which devices run a {watched.name} version affected by {advisory.id}?\n"
        "// Inventory, not exploitation. Snapshot tables, so there is no time filter.\n"
        f"let byVersion = {by_version};\n"
        "let byCve = DeviceTvmSoftwareVulnerabilities\n"
        f'    | where CveId == "{cve_id(advisory) or ""}"\n'
        "    | project DeviceName, SoftwareName, SoftwareVersion,"
        ' Basis = "Defender TVM CVE match";\n'
        "union byVersion, byCve\n"
        "| summarize Basis = make_set(Basis) by DeviceName, SoftwareName, SoftwareVersion\n"
        "| order by DeviceName asc"
    )
    return query, assumptions


def exposure_hunt(
    advisory: VulnAdvisory,
    watched: WatchedProduct,
    technique: str,
    schema: KqlSchema,
    retire: str,
) -> Hunt:
    query, assumptions = exposure_query(advisory, watched)
    return _code_hunt(
        advisory, f"{advisory.id}-exposure",
        f"Exposure: {watched.name} versions affected by {advisory.id}",
        ["DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities"],
        query, assumptions, technique, schema, retire,
        tuning="Scope to internet-facing hosts first; they are the ones T1190 reaches.",
        confidence=Confidence(
            score=90, rationale="Inventory match on structured version data, not exploitation."
        ),
    )  # fmt: skip


def _code_hunt(
    advisory: VulnAdvisory,
    draft_id: str,
    title: str,
    tables: list[str],
    query: str,
    assumptions: list[str],
    technique: str,
    schema: KqlSchema,
    retire: str,
    *,
    tuning: str,
    confidence: Confidence,
) -> Hunt:
    """An exposure hunt written by code. Each query bounds its own tables, so the lint's
    whole-query time-filter check is left out: snapshot tables need no bound."""
    draft = HuntDraft(
        title=title,
        technique_id=technique,
        tables=tables,
        query=query,
        evidence_quotes=[first_sentence(advisory.description or advisory_text(advisory))],
        expected_false_positives=[
            "Backported or vendor-patched builds that keep an old version string",
        ],
        tuning_notes=tuning,
        assumptions=assumptions,
        confidence=confidence,
    )
    lint = [f for f in lint_kql(query, draft.tables, schema) if f.code != "no_time_filter"]
    return Hunt(
        draft_id=draft_id,
        kind="exposure",
        technique_id=technique,
        draft=draft,
        lint=lint,
        review_outcome="not reviewed: written by code from structured advisory fields",
        needs_attention=any(f.severity == "error" for f in lint),
        attention_reasons=[f"lint {f.code}" for f in lint if f.severity == "error"],
        item_hash=item_hash(draft),
        model="code",
        prompt_version="exposure@v1",
        retire_when=retire,
    )


def generic_exposure_query(
    advisory: VulnAdvisory, target: Target
) -> tuple[str, list[str], list[str]] | None:
    """(query, tables, assumptions) for what Defender can see of a product that isn't on the
    watchlist, or None if there's nothing safe to match on. Every leg is bounded on its own:
    the TVM tables are snapshots, and DeviceInfo keeps the last week of reports."""
    legs: list[tuple[str, str, str]] = []
    assumptions = []
    cve = cve_id(advisory)
    if cve:
        legs.append(("byCve", "DeviceTvmSoftwareVulnerabilities", (
            f'    | where CveId == "{cve}"\n'
            "    | project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion,"
            ' Basis = "Defender TVM CVE match"'
        )))  # fmt: skip
        assumptions.append(
            "Defender lists a CVE against devices only once its own vulnerability data has it, "
            "which can take days for a new CVE: the name match below covers the gap."
        )
    if target.tvm_names:
        vendor = target.vendor.lower().replace(" ", "_") if target.vendor else None
        match = (f"SoftwareVendor in~ ({_kql_list([vendor])}) and " if vendor else "") + (
            f"SoftwareName in~ ({_kql_list(target.tvm_names)})"
        )
        # Each product keeps its own version ranges, so one product's range never matches
        # another product's install.
        per_product = []
        for product in target.products:
            ranges = [r for p in advisory.affected if kql_value(p.product) == product
                      for r in p.ranges]  # fmt: skip
            conditions = range_conditions(ranges)
            names = f"SoftwareName in~ ({_kql_list(software_names(product))})"
            per_product.append(
                f"({names} and ({' or '.join(conditions)}))" if conditions else f"({names})"
            )
        by_version = any("Version" in clause for clause in per_product)
        legs.append(("byName", "DeviceTvmSoftwareInventory", (
            f"    | where {match}\n"
            "    | extend Version = parse_version(SoftwareVersion)\n"
            + (f"    | where {' or '.join(per_product)}\n" if by_version else "")
            + "    | project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion,"
            ' Basis = "name and version range"'
        )))  # fmt: skip
        assumptions.append(
            f"Defender's software names are matched approximately (vendor {vendor!r}, names "
            f"{list(target.tvm_names)}): check the exact names in your tenant. An empty result "
            "can mean the names didn't match, not that nothing is exposed."
        )
        if not by_version:
            assumptions.append("No numeric version range in the advisory: every install is listed.")
    if target.vendor and not _is_package(advisory):
        legs.append(("byNetworkDevice", "DeviceInfo", (
            "    | where Timestamp > ago(7d)\n"
            f'    | where DeviceCategory == "NetworkDevice" and Vendor has "{target.vendor}"\n'
            "    | summarize arg_max(Timestamp, *) by DeviceId\n"
            "    | project DeviceName, SoftwareVendor = Vendor, SoftwareName = Model,"
            ' SoftwareVersion = OSVersion, Basis = "network device discovery"'
        )))  # fmt: skip
        assumptions.append(
            "Network devices appear only once Defender's device discovery has seen them, and "
            "their firmware version isn't always reported."
        )
    if _is_package(advisory):
        assumptions.append(
            "Defender doesn't inventory package dependencies: check SBOMs or lock files for "
            "the affected package itself."
        )
    if not legs:
        return None
    query = (
        f"// Which devices run {target.name} affected by {advisory.id}, as Defender sees them?\n"
        "// Inventory, not exploitation.\n"
        + "".join(f"let {name} = {table}\n{body};\n" for name, table, body in legs)
        + f"union isfuzzy=true {', '.join(name for name, _, _ in legs)}\n"
        "| summarize Basis = make_set(Basis) by DeviceName, SoftwareVendor, SoftwareName,"
        " SoftwareVersion\n"
        "| order by DeviceName asc"
    )
    return query, list(dict.fromkeys(table for _, table, _ in legs)), assumptions


def appliance_log_query(advisory: VulnAdvisory, target: Target) -> tuple[str, list[str]] | None:
    """(query, assumptions) for appliances from this vendor that send CEF logs to Sentinel,
    with the version they report. A separate hunt, because Sentinel and Defender tables can
    only be queried together in the unified portal."""
    if not target.vendor or _is_package(advisory):
        return None
    conditions = version_conditions(advisory)
    query = (
        f"// Which {target.vendor} appliances log to Sentinel, and what version do they report?\n"
        "// Inventory, not exploitation: CEF logs from the last day.\n"
        "CommonSecurityLog\n"
        "| where TimeGenerated > ago(1d)\n"
        f'| where DeviceVendor has "{target.vendor}"\n'
        + r'| extend Version = parse_version(extract(@"(\d+(?:\.\d+){1,3})", 1, DeviceVersion))'
        + "\n"
        + (f"| where {' or '.join(conditions)}\n" if conditions else "")
        + "| summarize LastSeen = max(TimeGenerated) by Computer, DeviceVendor, DeviceProduct,"
        " DeviceVersion\n"
        "| order by DeviceProduct asc, DeviceVersion asc"
    )
    assumptions = [
        f"Lists appliances that log as {target.vendor!r}: check DeviceProduct, which may name the "
        f"appliance rather than {target.product}, and note the version range applies to the "
        "affected product only.",
        "The version is read from DeviceVersion, which not every product fills in.",
    ]
    if not conditions:
        assumptions.append("No numeric version range in the advisory: every appliance is listed.")
    return query, assumptions


def generic_exposure_hunts(
    advisory: VulnAdvisory, target: Target, technique: str, schema: KqlSchema, retire: str
) -> list[Hunt]:
    confidence = Confidence(
        score=60,
        rationale="Approximate name match on structured version data, not exploitation.",
    )
    hunts = []
    if found := generic_exposure_query(advisory, target):
        query, tables, assumptions = found
        hunts.append(_code_hunt(
            advisory, f"{advisory.id}-exposure",
            f"Exposure: {target.name} versions affected by {advisory.id}",
            tables, query, assumptions, technique, schema, retire,
            tuning="Scope to internet-facing hosts first.", confidence=confidence,
        ))  # fmt: skip
    if found := appliance_log_query(advisory, target):
        query, assumptions = found
        hunts.append(_code_hunt(
            advisory, f"{advisory.id}-exposure-cef",
            f"Exposure (appliance logs): {target.vendor} versions affected by {advisory.id}",
            ["CommonSecurityLog"], query, assumptions, technique, schema, retire,
            tuning="Confirm DeviceProduct first; then patch or isolate what's listed.",
            confidence=confidence,
        ))  # fmt: skip
    return hunts


def _is_package(advisory: VulnAdvisory) -> bool:
    return any(p.ecosystem for p in advisory.affected)


def behaviour_surroundings(advisory: VulnAdvisory, extraction: PrepatchExtraction | None) -> str:
    """The advisory text plus the model's summary of it. Both derive from untrusted text, so
    the caller passes this as wrapped context, never as instructions."""
    text = advisory_text(advisory)
    if extraction:
        text += (
            f"\n\nModel-extracted summary (unverified): vector '{extraction.attack_vector}'; "
            f"component '{extraction.vulnerable_component}'; preconditions "
            f"{extraction.preconditions or 'none stated'}."
        )
    return text


def _affected(advisory: VulnAdvisory, clean=lambda value: value) -> str:
    return "; ".join(
        f"{clean(p.vendor or p.ecosystem or '') or ''} {clean(p.product) or '?'}"
        + (f" on {', '.join(filter(None, map(clean, p.platforms)))}" if p.platforms else "")
        + (f" ({', '.join(filter(None, map(clean, p.modules)))})" if p.modules else "")
        for p in advisory.affected
    )


def generic_behaviour_context(advisory: VulnAdvisory, target: Target, reasons: list[str]) -> str:
    """Facts for a product that isn't on the watchlist. Feed values go through kql_value, as
    these lines sit outside the wrapped context; no process names are offered, because none
    are known and a guessed one would look like a fact."""
    fixed = ", ".join(v for v in fixed_versions(advisory) if kql_value(v))
    lines = [
        f"This is a pre-patch hunt for {advisory.id}. Hunt for exploitation of this flaw in "
        f"{target.name}, not for the technique in general.",
        f"Affected: {_affected(advisory, kql_value) or 'see the advisory'}. "
        f"Fixed in: {fixed or 'no fixed version listed'}.",
        f"{target.name} isn't on the watchlist, so no process or service names are known for "
        "it: use only names the evidence gives, and don't guess others.",
        "A network appliance's own logs arrive in CommonSecurityLog (DeviceVendor, "
        "DeviceProduct, DeviceVersion); a web application's in W3CIISLog, and the web server's "
        "child processes in DeviceProcessEvents.",
        f"Why it was triaged: {'; '.join(reasons) or 'no signals recorded'}.",
    ]
    return "\n".join(lines)


def behaviour_context(advisory: VulnAdvisory, watched: WatchedProduct, signals: list[str]) -> str:
    """Facts from structured fields and the watchlist. Free text goes in the wrapped context."""
    affected = _affected(advisory)
    lines = [
        f"This is a pre-patch hunt for {advisory.id}. Hunt for exploitation of this flaw in "
        f"{watched.name}, not for the technique in general.",
        f"Affected: {affected or 'see the advisory'}. Fixed in: "
        f"{', '.join(fixed_versions(advisory)) or 'no fixed version listed'}.",
        f"{watched.name} runs as: {', '.join(watched.processes)}. "
        f"Commonly behind: {', '.join(watched.servers)}.",
        f"Exploitation signals: {'; '.join(signals) or 'none known'}.",
    ]
    return "\n".join(lines)
