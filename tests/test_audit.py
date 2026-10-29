import json
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from cti_agent.audit import GENESIS, AuditChainBroken, AuditLog, _hash, current_actor
from cti_agent.util.locks import InterProcessLock, LockTimeout


@pytest.fixture
def log(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "cti.db")
    audit.append(run_id="r1", actor="sam", action="review", item_ref="draft:a",
                 item_hash="sha256:1", decision="approve")  # fmt: skip
    audit.append(run_id="r1", actor="sam", action="review", item_ref="draft:b",
                 item_hash="sha256:2", decision="reject", reason="too broad")  # fmt: skip
    audit.append(run_id="r2", actor="sam", action="publish", decision="dry-run")
    return audit


def test_chain_verifies_and_links(log):
    log.verify()
    rows = log.entries()
    assert rows[0]["prev_hash"] == "0" * 64
    assert [r["prev_hash"] for r in rows[1:]] == [r["hash"] for r in rows[:-1]]


def lines(log):
    return log.path.read_text(encoding="utf-8").splitlines()


def write(log, new_lines):
    log.path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def test_changed_line_is_detected(log):
    rows = lines(log)
    row = json.loads(rows[1])
    row["decision"] = "approve"  # someone flips a rejection after the fact
    write(log, [rows[0], json.dumps(row), rows[2]])
    with pytest.raises(AuditChainBroken, match="line 2 was changed"):
        log.verify()


@pytest.mark.parametrize("change", ["delete", "reorder"])
def test_removed_or_reordered_line_is_detected(log, change):
    rows = lines(log)
    write(log, [rows[0], rows[2]] if change == "delete" else [rows[1], rows[0], rows[2]])
    with pytest.raises(AuditChainBroken, match="doesn't follow"):
        log.verify()


def test_latest_decision_wins(log):
    log.append(run_id="r1", actor="lee", action="review", item_ref="draft:b",
               item_hash="sha256:2b", decision="approve")  # fmt: skip
    latest = log.latest_decisions("r1")
    assert latest["draft:a"]["decision"] == "approve"
    assert latest["draft:b"]["decision"] == "approve" and latest["draft:b"]["actor"] == "lee"
    assert log.latest_decisions("r2") == {}


def test_mirrored_to_sqlite(log):
    with sqlite3.connect(log.db_path) as conn:
        rows = conn.execute("SELECT action, decision FROM audit ORDER BY id").fetchall()
    assert rows == [("review", "approve"), ("review", "reject"), ("publish", "dry-run")]


def test_actor(monkeypatch):
    monkeypatch.setenv("CTI_AGENT_REVIEWER", "analyst-1")
    assert current_actor() == "analyst-1"
    assert current_actor("explicit") == "explicit"


# --- several writers at once: the Slack bot's threads and a terminal ----------------------


def append_many(log, actor, n):
    for i in range(n):
        log.append(run_id="r1", actor=actor, action="review", item_ref=f"draft:{actor}-{i}",
                   item_hash=f"sha256:{i}", decision="approve")  # fmt: skip


def slow_reads(monkeypatch):
    """Widen the gap between reading the last hash and writing the next line."""
    read = AuditLog.entries

    def entries(self, run_id=None):
        rows = read(self, run_id)
        time.sleep(0.05)
        return rows

    monkeypatch.setattr(AuditLog, "entries", entries)


def in_threads(target, count):
    threads = [threading.Thread(target=target, args=(n,)) for n in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


class NoLock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


def test_without_the_lock_two_writers_fork_the_chain(tmp_path, monkeypatch):
    """The race the lock exists for, made certain: both writers read before either writes.
    Then either both lines chain onto the same one (a fork), or, where appends aren't atomic
    as on Windows, one line overwrites the other (a lost decision). Never two good lines."""
    log = AuditLog(tmp_path / "audit.jsonl")
    log._lock = NoLock()
    read, both_read = AuditLog.entries, threading.Barrier(2)

    def entries(self, run_id=None):
        rows = read(self, run_id)
        both_read.wait(timeout=10)
        return rows

    monkeypatch.setattr(AuditLog, "entries", entries)
    in_threads(lambda n: append_many(log, f"t{n}", 1), 2)
    try:
        log.verify()
    except AuditChainBroken:
        return  # forked, or torn into a line that isn't JSON
    assert len(log.path.read_text(encoding="utf-8").splitlines()) < 2  # one write was lost


def test_with_the_lock_the_same_race_keeps_one_chain(tmp_path, monkeypatch):
    log = AuditLog(tmp_path / "audit.jsonl")
    slow_reads(monkeypatch)
    in_threads(lambda n: append_many(log, f"t{n}", 2), 4)
    log.verify()
    assert len(log.entries()) == 8


def test_threads_appending_at_once_keep_one_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", tmp_path / "cti.db")
    in_threads(lambda n: append_many(log, f"t{n}", 25), 8)
    log.verify()
    assert len(log.entries()) == 200


WRITER = """
import sys
from pathlib import Path
from cti_agent.audit import AuditLog
log = AuditLog(Path(sys.argv[1]))
for i in range(int(sys.argv[3])):
    log.append(run_id="r1", actor=sys.argv[2], action="review", item_ref=f"draft:{i}",
               item_hash="sha256:x", decision="approve")
"""


def test_processes_appending_at_once_keep_one_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    others = [
        subprocess.Popen([sys.executable, "-c", WRITER, str(path), f"p{n}", "20"]) for n in range(3)
    ]
    append_many(AuditLog(path), "parent", 20)
    assert [p.wait(timeout=120) for p in others] == [0, 0, 0]
    log = AuditLog(path)
    log.verify()
    assert len(log.entries()) == 80


def test_a_reader_never_sees_half_a_line(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    append_many(log, "sam", 1)
    body = {
        "ts": "2026-10-28T00:00:00.000+00:00", "run_id": "r1", "actor": "lee",
        "action": "review", "item_ref": "draft:z", "item_hash": "sha256:z",
        "decision": "approve", "reason": None, "bulk": False, "detail": {},
        "prev_hash": log.entries()[-1]["hash"],
    }  # fmt: skip
    line = json.dumps({**body, "hash": _hash(body)}) + "\n"
    started = threading.Event()

    def slow_writer():
        with log.locked(), log.path.open("a", encoding="utf-8") as fh:
            fh.write(line[:40])
            fh.flush()
            started.set()
            time.sleep(0.3)
            fh.write(line[40:])

    writer = threading.Thread(target=slow_writer)
    writer.start()
    started.wait()
    log.verify()  # waits for the writer instead of reading half a line
    writer.join()
    assert [r["actor"] for r in log.entries()] == ["sam", "lee"]
    assert log.entries()[0]["prev_hash"] == GENESIS


def test_the_lock_is_reentrant_and_times_out_for_others(tmp_path):
    path = tmp_path / "x.lock"
    lock = InterProcessLock(path)
    with lock, lock:  # the same thread takes it twice
        failed = []

        def other():
            try:
                with InterProcessLock(path, timeout=0.2):
                    pass
            except LockTimeout:
                failed.append(True)

        thread = threading.Thread(target=other)
        thread.start()
        thread.join()
        assert failed == [True]
    with InterProcessLock(path, timeout=0.2):  # released after the outer block
        pass


HOLDER = """
import os, sys, time
from pathlib import Path
from cti_agent.util.locks import InterProcessLock
InterProcessLock(Path(sys.argv[1])).acquire()
print("held", flush=True)
time.sleep(float(sys.argv[2]))
os._exit(0)
"""


def test_a_lock_held_by_another_process_waits_then_frees_when_it_exits(tmp_path):
    path = tmp_path / "x.lock"
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(path), "1.0"],
                              stdout=subprocess.PIPE, text=True)  # fmt: skip
    assert holder.stdout.readline().strip() == "held"
    with (
        pytest.raises(LockTimeout, match="another cti-agent process"),
        InterProcessLock(path, timeout=0.2),
    ):
        pass
    holder.wait(timeout=30)  # exits without releasing; the OS frees the lock
    with InterProcessLock(path, timeout=10):
        pass
