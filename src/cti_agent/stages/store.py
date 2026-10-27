"""Stage 3: persist a run in SQLite. The STIX bundle file itself is written by the pipeline."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import stix2

from cti_agent.models import Hunt, Provenance, RunSummary

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    source_file     TEXT NOT NULL,
    source_sha256   TEXT NOT NULL,
    tlp             TEXT NOT NULL,
    status          TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    summary_json    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
    run_id        TEXT NOT NULL REFERENCES runs(run_id),
    stix_id       TEXT NOT NULL,
    type          TEXT NOT NULL,
    item_hash     TEXT,
    review_status TEXT NOT NULL DEFAULT 'pending',
    json          TEXT NOT NULL,
    PRIMARY KEY (run_id, stix_id)
);
CREATE TABLE IF NOT EXISTS drafts (
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    draft_id        TEXT NOT NULL,
    technique       TEXT NOT NULL,
    kind            TEXT NOT NULL,
    item_hash       TEXT NOT NULL,
    needs_attention INTEGER NOT NULL,
    review_status   TEXT NOT NULL DEFAULT 'pending',
    json            TEXT NOT NULL,
    PRIMARY KEY (run_id, draft_id)
);
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    run_id    TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    item_hash TEXT,
    decision  TEXT,
    detail    TEXT
);
"""

# Bundle members that describe the tool rather than the threat.
_SKIP_TYPES = {"marking-definition", "identity"}


def save_run(
    db_path: Path, provenance: Provenance, summary: RunSummary, bundle: stix2.Bundle
) -> int:
    """Insert the run and its STIX objects. Returns the number of objects stored."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        (
            provenance.run_id,
            obj["id"],
            obj["type"],
            obj.get("x_cti_agent_item_hash"),
            obj.serialize(),
        )
        for obj in bundle.objects
        if obj["type"] not in _SKIP_TYPES
    ]
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                provenance.run_id,
                provenance.ingested_at.isoformat(),
                provenance.source_file,
                provenance.source_sha256,
                provenance.tlp,
                summary.status,
                provenance.model_dump_json(),
                summary.model_dump_json(),
            ),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO objects (run_id, stix_id, type, item_hash, json) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def load_summary(db_path: Path, run_id: str) -> RunSummary | None:
    if not db_path.exists():
        return None
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute("SELECT summary_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return RunSummary.model_validate(json.loads(row[0])) if row else None


def save_drafts(db_path: Path, run_id: str, hunts: list[Hunt]) -> None:
    """Replace a run's drafts. Re-analysing a run resets them to pending review."""
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM drafts WHERE run_id = ?", (run_id,))
        conn.executemany(
            "INSERT INTO drafts (run_id, draft_id, technique, kind, item_hash, needs_attention,"
            " json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    h.draft_id,
                    h.technique_id,
                    h.kind,
                    h.item_hash,
                    int(h.needs_attention),
                    h.model_dump_json(),
                )
                for h in hunts
            ],
        )
