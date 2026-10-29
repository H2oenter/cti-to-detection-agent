"""Today's model spend, totalled from every run's trace, for the Slack bot's daily cap.

It counts every interface (terminal, eval and bot) on the UTC day the traces use. Replayed
calls cost nothing and are skipped; a line still being written is skipped too.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def spent_today(out_dir: Path, now: datetime) -> float:
    day = now.astimezone(UTC).date()
    start = datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp()
    total = 0.0
    for path in out_dir.rglob("trace.jsonl"):
        try:
            if path.stat().st_mtime < start:
                continue
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not str(row.get("ts", "")).startswith(day.isoformat()):
                continue
            if str(row.get("detail") or "").startswith("replayed"):
                continue
            total += float(row.get("est_cost_usd") or 0)
    return total
