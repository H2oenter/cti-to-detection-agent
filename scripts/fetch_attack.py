"""Download the ATT&CK Enterprise bundle once, pinned to one release.

Run from the repo root:  python scripts/fetch_attack.py

This is the only network call in setup. The CLI itself never downloads ATT&CK:
it reads data/attack/enterprise-attack.json, and tests use a small fixture.
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
# SHA-256 of the pinned release, checked after download. Update it when you change versions.
EXPECTED_SHA256: str | None = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
URL_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
DEST = Path("data/attack/enterprise-attack.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default=ATTACK_VERSION, help="ATT&CK release to fetch.")
    args = parser.parse_args()

    url = URL_TEMPLATE.format(version=args.version)
    expected = EXPECTED_SHA256 if args.version == ATTACK_VERSION else None
    DEST.parent.mkdir(parents=True, exist_ok=True)

    print(f"Downloading ATT&CK Enterprise {args.version} from {url}")
    digest = hashlib.sha256()
    with (
        urllib.request.urlopen(url, timeout=120) as response,
        tempfile.NamedTemporaryFile(dir=DEST.parent, delete=False, suffix=".part") as tmp,
    ):
        for block in iter(lambda: response.read(1 << 20), b""):
            digest.update(block)
            tmp.write(block)
    tmp_path = Path(tmp.name)
    sha256 = digest.hexdigest()

    if expected and sha256 != expected:
        tmp_path.unlink()
        print(f"SHA-256 mismatch: got {sha256}, expected {expected}", file=sys.stderr)
        return 1

    bundle = json.loads(tmp_path.read_text(encoding="utf-8"))
    techniques = [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern"]
    if bundle.get("type") != "bundle" or not techniques:
        tmp_path.unlink()
        print("Downloaded file is not an ATT&CK STIX bundle", file=sys.stderr)
        return 1

    tmp_path.replace(DEST)
    meta = {
        "version": args.version,
        "url": url,
        "sha256": sha256,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "attack_patterns": len(techniques),
    }
    DEST.with_name("VERSION").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {DEST} ({len(techniques)} attack-patterns, sha256 {sha256})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
