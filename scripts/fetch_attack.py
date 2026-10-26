"""Download the ATT&CK bundles once, each pinned to one release by SHA-256.

Run from the repo root:  python scripts/fetch_attack.py

These are the only network calls in setup. The CLI itself never downloads ATT&CK:
it reads data/attack/*.json, and tests use small fixtures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ATTACK_VERSION = "20.0"
# SHA-256 of each pinned release, checked after download. Update them when you change versions.
PINNED_SHA256: dict[str, str | None] = {
    "enterprise-attack": "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352",
    "mobile-attack": "824f7d8a37e7893b29e4c6ca6d87b5fbbf3b228ec6384f1a69ee20d523ff59e5",
}
URL_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "{domain}/{domain}-{version}.json"
)
DEST_DIR = Path("data/attack")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(domain: str, version: str) -> bool:
    dest = DEST_DIR / f"{domain}.json"
    url = URL_TEMPLATE.format(domain=domain, version=version)
    expected = PINNED_SHA256.get(domain) if version == ATTACK_VERSION else None

    if expected and dest.exists() and _sha256(dest) == expected:
        print(f"{dest} already matches the pinned SHA-256; not downloading again")
        sha256 = expected
    else:
        print(f"Downloading ATT&CK {domain} {version} from {url}")
        digest = hashlib.sha256()
        with (
            urllib.request.urlopen(url, timeout=120) as response,
            tempfile.NamedTemporaryFile(dir=DEST_DIR, delete=False, suffix=".part") as tmp,
        ):
            for block in iter(lambda: response.read(1 << 20), b""):
                digest.update(block)
                tmp.write(block)
        tmp_path = Path(tmp.name)
        sha256 = digest.hexdigest()
        if expected and sha256 != expected:
            tmp_path.unlink()
            print(
                f"SHA-256 mismatch for {domain}: got {sha256}, expected {expected}", file=sys.stderr
            )
            return False
        tmp_path.replace(dest)

    bundle = json.loads(dest.read_text(encoding="utf-8"))
    techniques = [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern"]
    if bundle.get("type") != "bundle" or not techniques:
        print(f"{dest} is not an ATT&CK STIX bundle", file=sys.stderr)
        return False

    meta = {
        "domain": domain,
        "version": version,
        "url": url,
        "sha256": sha256,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "attack_patterns": len(techniques),
    }
    dest.with_suffix(".version.json").write_text(json.dumps(meta, indent=2) + "\n", "utf-8")
    pin_note = "" if expected else "  (not pinned yet: add it to PINNED_SHA256)"
    print(f"Saved {dest}: {len(techniques)} attack-patterns, sha256 {sha256}{pin_note}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default=ATTACK_VERSION, help="ATT&CK release to fetch.")
    parser.add_argument(
        "--domain", choices=[*PINNED_SHA256, "all"], default="all", help="Which matrix to fetch."
    )
    args = parser.parse_args()
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    domains = list(PINNED_SHA256) if args.domain == "all" else [args.domain]
    return 0 if all(fetch(d, args.version) for d in domains) else 1


if __name__ == "__main__":
    sys.exit(main())
