"""Start a gold-label file for a report, label it, and save it. No model, no network.

Run from the repo root:
    python scripts/gold_draft.py reports/aa26-222a.pdf --stix reports/aa26-222a-stix.json
    python scripts/gold_draft.py --label eval/gold/aa26-222a.draft.json

The first writes eval/gold/<report_id>.draft.json: every candidate in the report text. --label
then shows each one with its page and the text around it, takes one key per decision, asks
for the metadata, and saves eval/gold/<report_id>.json once the eval's checks pass. Stopping
part-way is fine: decisions are saved as they're made. If you edit the draft's "gold" section
by hand instead, --finish runs the same checks and saves it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from rich.console import Console

    from cti_agent.attack.attack_index import AttackIndex
    from cti_agent.config import Settings
    from cti_agent.evaluation.candidates import draft, finish_draft
    from cti_agent.evaluation.gold import GoldError
    from cti_agent.evaluation.labelling import run_labelling
    from cti_agent.inputs import load_source
except ModuleNotFoundError as exc:  # a Python outside the project's virtual environment
    sys.exit(
        f"{exc}. Run it with the project's Python: .venv\\Scripts\\python on Windows, "
        ".venv/bin/python elsewhere, or activate .venv first."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "report", type=Path, nargs="?", help="The report file, e.g. reports/aa26-222a.pdf"
    )
    parser.add_argument("--stix", type=Path, help="The publisher's STIX JSON for this report")
    parser.add_argument("--id", help="Report ID (default: the file name, e.g. aa26-222a)")
    parser.add_argument("--out", type=Path, default=Path("eval/gold"))
    parser.add_argument(
        "--label",
        type=Path,
        metavar="DRAFT",
        help="Decide each candidate in a draft, one key at a time, then save",
    )
    parser.add_argument(
        "--all", action="store_true", help="With --label: go through decided candidates again"
    )
    parser.add_argument(
        "--finish",
        type=Path,
        metavar="DRAFT",
        help="Check a hand-edited draft and save it as <report_id>.json",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing gold file, or a draft that has decisions in it",
    )
    args = parser.parse_args()
    if sum(map(bool, (args.report, args.label, args.finish))) != 1:
        parser.error(
            "give a report to start a draft, --label DRAFT to label one, "
            "or --finish DRAFT to save one you edited by hand"
        )
    if args.label:
        return label(args.label, args.force, args.all)
    if args.finish:
        return finish(args.finish, args.force)

    report_id = args.id or args.report.stem.lower()
    path = args.out / f"{report_id}.draft.json"
    if _has_decisions(path) and not args.force:
        print(
            f"Not overwritten: {path} already holds labelling decisions. Carry on with "
            f"--label {path.as_posix()}, or pass --force to start again.",
            file=sys.stderr,
        )
        return 1
    result = draft(load_source(args.report), report_id, args.stix)
    args.out.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    ind = result["indicator_candidates"]
    print(f"Wrote {path}")
    print(
        f"  indicators: {len(ind['in_text_and_stix'])} in text and STIX (pre-filled), "
        f"{len(ind['text_only'])} text only (you decide), "
        f"{len(ind['stix_only'])} STIX only (left out)"
    )
    print(
        f"  techniques: {len(result['technique_candidates'])} IDs in the text (pre-filled; "
        "move tool-capability IDs to optional_techniques)"
    )
    print(f"  CVEs: {len(result['cve_candidates'])}")
    print(f"Next: python scripts/gold_draft.py --label {path.as_posix()}")
    return 0


def label(draft_path: Path, force: bool, include_decided: bool) -> int:
    try:
        outcome = run_labelling(
            draft_path,
            Console(),
            ask=_ask_key,
            ask_text=_ask_text,
            names=_technique_names(),
            include_decided=include_decided,
        )
    except KeyboardInterrupt:
        print("\nStopped. Every decision you made is saved in the draft.")
        return 1
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"Can't label {draft_path}: {exc!r}", file=sys.stderr)
        return 1
    if not outcome.complete:
        return 0
    return finish(draft_path, force)


def _ask_key(menu: str, keys: list[str]) -> str:
    while True:
        key = input(f"{menu}: ").strip().lower()
        if key in keys:
            return key
        print(f"  Press one of: {' '.join(keys)}")


def _ask_text(prompt: str, default: str) -> str:
    answer = input(f"{prompt} [{default}]: " if default else f"{prompt}: ").strip()
    return answer or default


def _technique_names():
    """ATT&CK names, if the bundles have been downloaded; the IDs are enough without them."""
    try:
        index = AttackIndex(*Settings(_env_file=None).attack_bundles())
    except (OSError, ValueError):
        return lambda attack_id: None
    return lambda attack_id: info.name if (info := index.lookup(attack_id)) else None


def _has_decisions(path: Path) -> bool:
    try:
        return bool(json.loads(path.read_text(encoding="utf-8"))["labelling"]["decisions"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return False


def finish(draft_path: Path, force: bool) -> int:
    try:
        done = finish_draft(draft_path, force=force)
    except GoldError as exc:
        print(f"Not saved: {exc}", file=sys.stderr)
        return 1
    g = done.gold
    print(f"Saved {done.path.as_posix()}")
    print(f"  indicators: {len(g.indicators)} required, {len(g.optional_indicators)} optional")
    print(f"  techniques: {len(g.techniques)} required, {len(g.optional_techniques)} optional")
    print(f"  actors: {', '.join(g.actors)}   CVEs: {len(g.cves)}")
    print(f"  pinned to {g.source.file} (SHA-256 {g.source.sha256[:12]}...), which still matches")
    if done.made:
        print(f"  decided: {done.made}")
    for note in done.notes:
        print(f"Check: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
