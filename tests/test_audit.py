import json
import sqlite3

import pytest

from cti_agent.audit import AuditChainBroken, AuditLog, current_actor


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
