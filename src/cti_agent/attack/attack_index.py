"""Technique lookups against a locally cached ATT&CK bundle. No network at runtime."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mitreattack.stix20 import MitreAttackData


@dataclass(frozen=True)
class TechniqueInfo:
    attack_id: str
    name: str
    tactics: tuple[str, ...]  # ATT&CK tactic shortnames, e.g. "initial-access"
    revoked: bool
    deprecated: bool
    revoked_by: str | None  # ATT&CK ID of the replacement, if revoked
    url: str | None


class AttackLookup(Protocol):
    @property
    def domain(self) -> str: ...

    def lookup(self, attack_id: str) -> TechniqueInfo | None: ...


class AttackIndex:
    def __init__(self, bundle_path: Path) -> None:
        if not bundle_path.exists():
            raise FileNotFoundError(
                f"ATT&CK bundle not found at {bundle_path}. Run: python scripts/fetch_attack.py"
            )
        self.bundle_path = bundle_path
        self._data = MitreAttackData(stix_filepath=str(bundle_path))
        self._cache: dict[str, TechniqueInfo | None] = {}
        self._domain: str | None = None

    @property
    def domain(self) -> str:
        """Which ATT&CK matrix this bundle covers, e.g. "enterprise-attack v20.0"."""
        if self._domain is None:
            techniques = self._data.get_techniques(remove_revoked_deprecated=False)
            domains = techniques[0].get("x_mitre_domains", []) if techniques else []
            version = f" v{self.version}" if self.version else ""
            self._domain = f"{domains[0] if domains else 'unknown'}{version}"
        return self._domain

    @property
    def version(self) -> str | None:
        version_file = self.bundle_path.with_name("VERSION")
        if version_file.exists():
            return json.loads(version_file.read_text(encoding="utf-8")).get("version")
        return None

    def lookup(self, attack_id: str) -> TechniqueInfo | None:
        attack_id = attack_id.strip().upper()
        if attack_id not in self._cache:
            self._cache[attack_id] = self._load(attack_id)
        return self._cache[attack_id]

    def _load(self, attack_id: str) -> TechniqueInfo | None:
        obj = self._data.get_object_by_attack_id(attack_id, "attack-pattern")
        if obj is None:
            return None
        revoked = bool(obj.get("revoked", False))
        revoked_by = None
        if revoked:
            replacement = self._data.get_revoking_object(obj["id"])
            if replacement is not None:
                revoked_by = self._data.get_attack_id(replacement["id"])
        url = next(
            (
                ref.get("url")
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        tactics = tuple(
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        )
        return TechniqueInfo(
            attack_id=attack_id,
            name=obj["name"],
            tactics=tactics,
            revoked=revoked,
            deprecated=bool(obj.get("x_mitre_deprecated", False)),
            revoked_by=revoked_by,
            url=url,
        )
