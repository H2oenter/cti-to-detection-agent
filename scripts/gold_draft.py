"""Start a gold-label file for a report. Deterministic: no model, no network.

Run from the repo root:
    python scripts/gold_draft.py reports/aa26-222a.pdf --stix reports/aa26-222a-stix.json

Writes eval/gold/<report_id>.draft.json. Review every candidate against the report and
eval/gold/README.md, then save the edited "gold" section as eval/gold/<report_id>.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from cti_agent.evaluation.candidates import draft
    from cti_agent.inputs import load_source
except ModuleNotFoundError as exc:  # a Python outside the project's virtual environment
    sys.exit(f"{exc}. Run it with the project's Python: .venv\\Scripts\\python on Windows, "
             ".venv/bin/python elsewhere, or activate .venv first.")  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="The report file, e.g. reports/aa26-222a.pdf")
    parser.add_argument("--stix", type=Path, help="The publisher's STIX JSON for this report")
    parser.add_argument("--id", help="Report ID (default: the file name, e.g. aa26-222a)")
    parser.add_argument("--out", type=Path, default=Path("eval/gold"))
    args = parser.parse_args()

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
    print("Next: review it against eval/gold/README.md, then save 'gold' as "
          f"eval/gold/{report_id}.json")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
