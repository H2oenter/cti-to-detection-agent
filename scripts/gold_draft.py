"""Start a gold-label file for a report, then check and save it. No model, no network.

Run from the repo root:
    python scripts/gold_draft.py reports/aa26-222a.pdf --stix reports/aa26-222a-stix.json
    python scripts/gold_draft.py --finish eval/gold/aa26-222a.draft.json

The first writes eval/gold/<report_id>.draft.json. Review every candidate against the report
and eval/gold/README.md, and edit its "gold" section. --finish then checks that section the
way the eval will read it and saves it as eval/gold/<report_id>.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from cti_agent.evaluation.candidates import draft, finish_draft
    from cti_agent.evaluation.gold import GoldError
    from cti_agent.inputs import load_source
except ModuleNotFoundError as exc:  # a Python outside the project's virtual environment
    sys.exit(f"{exc}. Run it with the project's Python: .venv\\Scripts\\python on Windows, "
             ".venv/bin/python elsewhere, or activate .venv first.")  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, nargs="?",
                        help="The report file, e.g. reports/aa26-222a.pdf")  # fmt: skip
    parser.add_argument("--stix", type=Path, help="The publisher's STIX JSON for this report")
    parser.add_argument("--id", help="Report ID (default: the file name, e.g. aa26-222a)")
    parser.add_argument("--out", type=Path, default=Path("eval/gold"))
    parser.add_argument("--finish", type=Path, metavar="DRAFT",
                        help="Check a labelled draft and save it as <report_id>.json")  # fmt: skip
    parser.add_argument("--force", action="store_true",
                        help="With --finish: replace an existing <report_id>.json")  # fmt: skip
    args = parser.parse_args()
    if bool(args.report) == bool(args.finish):
        parser.error("give a report to start a draft, or --finish DRAFT to save one")
    if args.finish:
        return finish(args.finish, args.force)

    report_id = args.id or args.report.stem.lower()
    result = draft(load_source(args.report), report_id, args.stix)
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{report_id}.draft.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    ind = result["indicator_candidates"]
    print(f"Wrote {path}")
    print(f"  indicators: {len(ind['in_text_and_stix'])} in text and STIX (pre-filled), "
          f"{len(ind['text_only'])} text only (you decide), "
          f"{len(ind['stix_only'])} STIX only (left out)")  # fmt: skip
    print(f"  techniques: {len(result['technique_candidates'])} IDs in the text (pre-filled; "
          "move tool-capability IDs to optional_techniques)")  # fmt: skip
    print(f"  CVEs: {len(result['cve_candidates'])}")
    print(f"Next: label it against eval/gold/README.md, then run --finish {path.as_posix()}")
    return 0


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
    for note in done.notes:
        print(f"Check: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
