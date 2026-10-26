"""Technique lookups against locally cached ATT&CK bundles. No network at runtime.

Several matrices can be loaded (Enterprise, then Mobile). Technique IDs don't overlap
between them, and each answer says which matrix it came from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mitreattack.stix20 import MitreAttackData

# Each matrix names its kill chain differently; the external reference source is shared.
KILL_CHAINS = {
    "enterprise-attack": "mitre-attack",
    "mobile-attack": "mitre-mobile-attack",
    "ics-attack": "mitre-ics-attack",
}


@dataclass(frozen=True)
class TechniqueInfo:
    attack_id: str
    name: str
    domain: str  # "enterprise-attack", "mobile-attack", ...
    tactics: tuple[str, ...]  # tactic shortnames, e.g. "initial-access"
    revoked: bool
    deprecated: bool
    revoked_by: str | None  # ATT&CK ID of the replacement, if revoked
    url: str | None

    @property
    def kill_chain(self) -> str:
        return KILL_CHAINS.get(self.domain, "mitre-attack")


class AttackLookup(Protocol):
    @property
    def description(self) -> str: ...

    def lookup(self, attack_id: str) -> TechniqueInfo | None: ...


class _Matrix:
    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(
                f"ATT&CK bundle not found at {path}. Run: python scripts/fetch_attack.py"
            )
        self.data = MitreAttackData(stix_filepath=str(path))
        techniques = self.data.get_techniques(remove_revoked_deprecated=False)
        domains = techniques[0].get("x_mitre_domains", []) if techniques else []
        self.domain = domains[0] if domains else "unknown"
        version_file = path.with_suffix(".version.json")
        self.version = (
            json.loads(version_file.read_text(encoding="utf-8")).get("version")
            if version_file.exists()
            else None
        )


class AttackIndex:
    def __init__(self, *bundle_paths: Path) -> None:
        if not bundle_paths:
            raise ValueError("at least one ATT&CK bundle is needed")
        self._matrices = [_Matrix(p) for p in bundle_paths]
        self._cache: dict[str, TechniqueInfo | None] = {}

    @property
    def description(self) -> str:
        """What is loaded, e.g. "enterprise-attack v20.0, mobile-attack v20.0"."""
        return ", ".join(
            f"{m.domain} v{m.version}" if m.version else m.domain for m in self._matrices
        )

    def lookup(self, attack_id: str) -> TechniqueInfo | None:
        attack_id = attack_id.strip().upper()
        if attack_id not in self._cache:
            self._cache[attack_id] = next(
                (info for m in self._matrices if (info := _load(m, attack_id))), None
            )
        return self._cache[attack_id]


def _load(matrix: _Matrix, attack_id: str) -> TechniqueInfo | None:
    data = matrix.data
    obj = data.get_object_by_attack_id(attack_id, "attack-pattern")
    if obj is None:
        return None
    revoked = bool(obj.get("revoked", False))
    revoked_by = None
    if revoked:
        replacement = data.get_revoking_object(obj["id"])
        if replacement is not None:
            revoked_by = data.get_attack_id(replacement["id"])
    url = next(
        (
            ref.get("url")
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ),
        None,
    )
    kill_chain = KILL_CHAINS.get(matrix.domain, "mitre-attack")
    tactics = tuple(
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == kill_chain
    )
    return TechniqueInfo(
        attack_id=attack_id,
        name=obj["name"],
        domain=matrix.domain,
        tactics=tactics,
        revoked=revoked,
        deprecated=bool(obj.get("x_mitre_deprecated", False)),
        revoked_by=revoked_by,
        url=url,
    )
