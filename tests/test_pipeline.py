"""End-to-end ingest with no network: a fake model, then record and replay."""

import json
import sqlite3
from collections import Counter

import pytest
import stix2
from conftest import BAD_ITEMS, FIXTURE_REPORT, GOOD_ITEMS, FakeModel

from cti_agent.llm.client import RecordingClient, ReplayClient
from cti_agent.pipeline import IngestBlocked, run_ingest
from cti_agent.trace import read_trace


def test_ingest_end_to_end(settings, attack_index):
    result = run_ingest(FIXTURE_REPORT, "CLEAR", settings, FakeModel(), attack=attack_index)

    assert result.summary.status == "complete"
    assert len(result.validation.accepted) == len(GOOD_ITEMS)
    assert Counter(r.reason for r in result.validation.rejected) == Counter(
        reason for _, reason in BAD_ITEMS
    )
    # Nothing from the planted instructions survives.
    accepted_values = json.dumps(result.validation.model_dump(mode="json")["accepted"])
    assert "8.8.8.8" not in accepted_values and "canary-7f3a9" not in accepted_values

    out = result.out_dir
    for name in ("extraction.raw.json", "validated.json", "rejected.jsonl", "bundle.json",
                 "trace.jsonl", "provenance.json", "run_summary.json"):  # fmt: skip
        assert (out / name).exists(), name

    # The raw output keeps what the model said, including the injected values, for the eval.
    raw = (out / "extraction.raw.json").read_text(encoding="utf-8")
    assert "canary-7f3a9-injected.net" in raw

    bundle = stix2.parse((out / "bundle.json").read_text(encoding="utf-8"), allow_custom=True)
    types = Counter(o["type"] for o in bundle.objects)
    assert types["indicator"] == 4 and types["attack-pattern"] == 3
    assert types["threat-actor"] == 1 and types["vulnerability"] == 1 and types["report"] == 1
    assert types["relationship"] == 4 + 3 + 1

    with sqlite3.connect(settings.db_path) as conn:
        [(status,)] = conn.execute("SELECT status FROM runs WHERE run_id = ?", (result.run_id,))
        [(n,)] = conn.execute("SELECT COUNT(*) FROM objects WHERE run_id = ?", (result.run_id,))
    assert status == "complete" and n == sum(types.values()) - 2  # minus marking + identity

    stages = [line["stage"] for line in read_trace(out / "trace.jsonl")]
    assert stages == ["ingest", "collector", "validator", "store"]


def test_multi_chunk_overlap_is_deduplicated(settings, attack_index):
    small = settings.model_copy(update={"chunk_target_tokens": 150, "chunk_overlap_ratio": 0.3})
    model = FakeModel()
    result = run_ingest(FIXTURE_REPORT, "CLEAR", small, model, attack=attack_index)
    assert len(model.calls) > 2
    assert len(result.validation.accepted) == len(GOOD_ITEMS)
    assert result.summary.chunks_done == result.summary.chunks_total == len(model.calls)


def test_tlp_red_is_blocked_before_any_model_call(settings, attack_index):
    model = FakeModel()
    with pytest.raises(IngestBlocked, match="RED"):
        run_ingest(FIXTURE_REPORT, "RED", settings, model, attack=attack_index)
    assert model.calls == []
    assert not settings.out_dir.exists()


def test_budget_stops_the_run_cleanly(settings, attack_index):
    tight = settings.model_copy(
        update={
            "chunk_target_tokens": 150,
            "extract_max_output_tokens": 100,
            "max_tokens_per_run": 2000,
        }
    )
    model = FakeModel()
    result = run_ingest(FIXTURE_REPORT, "CLEAR", tight, model, attack=attack_index)
    s = result.summary
    assert s.status == "partial" and s.stop_reason == "budget"
    assert 0 < s.chunks_done < s.chunks_total
    assert s.input_tokens + s.output_tokens <= 2000
    outcomes = [line["outcome"] for line in read_trace(result.out_dir / "trace.jsonl")]
    assert "skipped_budget" in outcomes


def test_zero_budget_makes_no_calls(settings, attack_index):
    model = FakeModel()
    broke = settings.model_copy(update={"max_tokens_per_run": 10})
    result = run_ingest(FIXTURE_REPORT, "CLEAR", broke, model, attack=attack_index)
    assert model.calls == []
    assert result.summary.status == "failed" and result.summary.stop_reason == "budget"


def test_record_then_replay_gives_identical_results(settings, tmp_path, attack_index):
    fixtures = tmp_path / "llm"
    first = run_ingest(
        FIXTURE_REPORT, "CLEAR", settings, RecordingClient(FakeModel(), fixtures),
        attack=attack_index,
    )  # fmt: skip
    recorded = list(fixtures.glob("*.json"))
    assert recorded
    assert "ANTHROPIC" not in recorded[0].read_text(encoding="utf-8")

    second = run_ingest(
        FIXTURE_REPORT, "CLEAR", settings, ReplayClient(fixtures), attack=attack_index
    )
    hashes = lambda r: sorted(a.item_hash for a in r.validation.accepted)  # noqa: E731
    assert hashes(first) == hashes(second)
    assert first.run_id != second.run_id
    replayed = [line for line in read_trace(second.out_dir / "trace.jsonl")
                if line["stage"] == "collector"]  # fmt: skip
    assert all(line["detail"].startswith("replayed") for line in replayed)
