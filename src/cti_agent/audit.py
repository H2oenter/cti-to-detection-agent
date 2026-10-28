"""Append-only, hash-chained audit log of reviews, edits and publishes (design rule 8).

Each line carries the hash of the line before it and a hash of itself, so editing,
reordering or deleting any earlier line breaks verification. Review and publish refuse
to start on a broken chain. The JSONL file is the record; SQLite holds a copy for queries.

Reads and writes hold a lock shared across threads and processes: two writers that both
read the same last hash would fork the chain, and a reader that caught half a line would
raise a false tamper alarm.
"""

from __future__ import annotations

import getpass
import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.util.locks import InterProcessLock
from cti_agent.util.normalise import canonical_json, sha256_bytes

GENESIS = "0" * 64


class AuditChainBroken(Exception):
    pass


def current_actor(explicit: str | None = None) -> str:
    return explicit or os.environ.get("CTI_AGENT_REVIEWER") or getpass.getuser()


def audit_log_for(settings) -> AuditLog:
    """The one audit log for a configuration (any object with out_dir and db_path)."""
    return AuditLog(settings.out_dir / "audit.jsonl", settings.db_path)


def _hash(body: dict) -> str:
    return sha256_bytes(canonical_json(body).encode("utf-8"))


class AuditLog:
    def __init__(self, path: Path, db_path: Path | None = None) -> None:
        self.path = path
        self.db_path = db_path
        self._lock = InterProcessLock(path.with_name(path.name + ".lock"))

    def locked(self) -> InterProcessLock:
        """Hold this around a read, decide and write sequence. It is reentrant, so the
        reads and appends inside take it again freely."""
        return self._lock

    def entries(self, run_id: str | None = None) -> list[dict]:
        with self._lock:
            if not self.path.exists():
                return []
            with self.path.open(encoding="utf-8") as fh:
                rows = [json.loads(line) for line in fh if line.strip()]
        return [r for r in rows if run_id is None or r["run_id"] == run_id]

    def verify(self) -> None:
        """Raise AuditChainBroken with the first bad line, if any."""
        with self._lock:
            self._verify()

    def _verify(self) -> None:
        if not self.path.exists():
            return
        previous = GENESIS
        with self.path.open(encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditChainBroken(f"line {number} is not valid JSON") from exc
                stored = row.pop("hash", None)
                if row.get("prev_hash") != previous:
                    raise AuditChainBroken(
                        f"line {number} doesn't follow line {number - 1}: "
                        "a line was removed, reordered or changed"
                    )
                if _hash(row) != stored:
                    raise AuditChainBroken(f"line {number} was changed after it was written")
                previous = stored

    def append(
        self,
        *,
        run_id: str,
        actor: str,
        action: str,
        item_ref: str | None = None,
        item_hash: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        bulk: bool = False,
        detail: dict | None = None,
    ) -> dict:
        with self._lock:
            entries = self.entries()
            body = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "run_id": run_id,
                "actor": actor,
                "action": action,
                "item_ref": item_ref,
                "item_hash": item_hash,
                "decision": decision,
                "reason": reason,
                "bulk": bulk,
                "detail": detail or {},
                "prev_hash": entries[-1]["hash"] if entries else GENESIS,
            }
            row = {**body, "hash": _hash(body)}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._mirror(row)
        return row

    def latest_decisions(self, run_id: str) -> dict[str, dict]:
        """The most recent review decision per item in a run, keyed by item_ref."""
        latest: dict[str, dict] = {}
        for row in self.entries(run_id):
            if row["action"] == "review" and row["item_ref"]:
                latest[row["item_ref"]] = row
        return latest

    def _mirror(self, row: dict) -> None:
        if self.db_path is None:
            return
        from cti_agent.stages.store import SCHEMA  # local import: store imports models only

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT INTO audit (ts, run_id, actor, action, item_hash, decision, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row["ts"],
                    row["run_id"],
                    row["actor"],
                    row["action"],
                    row["item_hash"],
                    row["decision"],
                    json.dumps(
                        {k: row[k] for k in ("item_ref", "reason", "bulk", "detail", "hash")}
                    ),
                ),
            )
