"""Stages 4-5 end to end on the recorded AA23-320A ingest, with fake analyst models."""

import json
import sqlite3

import pytest
from conftest import FakeAnalyst

from cti_agent.models import LintFinding, ReviewScores
from cti_agent.outputs.brief_out import check_summary
from cti_agent.pipeline import AnalyseError, IngestBlocked, run_analyse
from cti_agent.stages.analyst import check_evidence
from cti_agent.stages.reviewer import attention_reasons
from cti_agent.trace import read_trace


def analyse(aa23_run, settings, aa23_attack, model=None, **kwargs):
    return run_analyse(aa23_run, settings, model or FakeAnalyst(), attack=aa23_attack, **kwargs)


def test_analyse_end_to_end(aa23_run, settings, aa23_attack):
    model = FakeAnalyst()
    result = analyse(aa23_run, settings, aa23_attack, model)
    out = settings.out_dir / aa23_run

    states = {e.attack_id: e.state for e in result.coverage}
    assert states["T1621"] == "covered"
    assert states["T1566.004"] == "partial"  # sample rule covers T1566 only
    assert states["T1660"] == states["T1451"] == "not_applicable"
    assert len(result.hunts) == settings.max_hunts_per_run == 5
    assert result.not_drafted  # more gaps than the cap
    # Pre-compromise techniques are not chosen while huntable gaps remain.
    chosen = {h.technique_id for h in result.hunts}
    assert not chosen & {"T1589", "T1594", "T1593.001", "T1597.002", "T1583.001"}
    assert all(h.review and not h.needs_attention for h in result.hunts)
    assert result.summary_source == "model"

    assert sorted(p.name for p in (out / "hunts").iterdir()) == sorted(
        f"{h.draft_id}.kql" for h in result.hunts
    )
    kql = (out / "hunts" / f"{result.hunts[0].draft_id}.kql").read_text(encoding="utf-8")
    assert kql.startswith("// DRAFT HUNT") and "Reviewer: faithful 4" in kql
    brief = (out / "brief.md").read_text(encoding="utf-8")
    for heading in ("## For leadership", "## For detection engineers", "### Provenance"):
        assert heading in brief
    assert json.loads((out / "analysis.json").read_text(encoding="utf-8"))["run_id"] == aa23_run

    with sqlite3.connect(settings.db_path) as conn:
        rows = conn.execute(
            "SELECT review_status FROM drafts WHERE run_id = ?", (aa23_run,)
        ).fetchall()
    assert rows == [("pending",)] * 5

    stages = [line["stage"] for line in read_trace(out / "trace.jsonl")]
    assert stages.count("analyst") == 6 and stages.count("reviewer") == 5  # 6 = coverage + 5
    assert "brief" in stages
    # The analyst saw evidence only inside the untrusted wrapper.
    drafting = [user for name, user in model.calls if name == "HuntDraft"]
    assert all("<untrusted_report>" in user for user in drafting)


def test_poisoned_draft_is_flagged_not_hidden(aa23_run, settings, aa23_attack):
    first = analyse(aa23_run, settings, aa23_attack).hunts[0].technique_id
    result = analyse(
        aa23_run, settings, aa23_attack, FakeAnalyst(bad_query_for={first}), force=True
    )
    hunt = next(h for h in result.hunts if h.technique_id == first)
    assert "external_data" in {f.code for f in hunt.lint if f.severity == "error"}
    assert hunt.needs_attention and "lint errors" in hunt.attention_reasons[0]


def test_low_review_score_needs_attention(aa23_run, settings, aa23_attack):
    first = analyse(aa23_run, settings, aa23_attack).hunts[0].technique_id
    result = analyse(
        aa23_run, settings, aa23_attack, FakeAnalyst(low_scores_for={first}), force=True
    )
    hunt = next(h for h in result.hunts if h.technique_id == first)
    assert hunt.attention_reasons == ["kql_correct scored 2"]


def test_refused_draft_is_listed_not_dropped(aa23_run, settings, aa23_attack):
    first = analyse(aa23_run, settings, aa23_attack).hunts[0].technique_id
    result = analyse(aa23_run, settings, aa23_attack, FakeAnalyst(refuse={first}), force=True)
    assert first not in {h.technique_id for h in result.hunts}
    assert f"{first} (refused)" in result.not_drafted


def test_invented_number_falls_back_to_template(aa23_run, settings, aa23_attack):
    model = FakeAnalyst(summary=["Coverage is 87% complete.", "Two.", "Three."])
    result = analyse(aa23_run, settings, aa23_attack, model)
    assert result.summary_source == "template"
    assert "87" not in result.leadership_summary


def test_second_run_needs_force(aa23_run, settings, aa23_attack):
    analyse(aa23_run, settings, aa23_attack)
    with pytest.raises(AnalyseError, match="--force"):
        analyse(aa23_run, settings, aa23_attack)


def test_tlp_gate_applies_again(aa23_run, settings, aa23_attack):
    path = settings.out_dir / aa23_run / "provenance.json"
    provenance = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**provenance, "tlp": "RED"}), encoding="utf-8")
    model = FakeAnalyst()
    with pytest.raises(IngestBlocked):
        analyse(aa23_run, settings, aa23_attack, model)
    assert model.calls == []


def test_check_evidence():
    given = ["Scattered Spider used MFA fatigue (T1621)."]
    assert check_evidence(["used MFA fatigue"], given) == []
    assert [f.code for f in check_evidence([], given)] == ["no_evidence"]
    assert [f.code for f in check_evidence(["invented text"], given)] == ["evidence_not_given"]


def test_attention_reasons():
    good = ReviewScores(faithful=5, kql_correct=4, actionable=3, calibrated=3, reasons=[])
    assert attention_reasons(good, [], "ok") == []
    error = LintFinding(severity="error", code="unknown_table", message="m")
    warning = LintFinding(severity="warning", code="no_time_filter", message="m")
    assert attention_reasons(good, [error, warning], "ok") == ["lint errors: unknown_table"]
    assert attention_reasons(None, [], "refused") == ["no review (refused)"]


@pytest.mark.parametrize(
    ("sentences", "ok"),
    [
        (["Actor X is active.", "It maps to 41 techniques.", "Hunts await review."], True),
        (["Actor X is active.", "Coverage is 55%.", "Hunts await review."], False),
        (["See T9999.", "b.", "c."], False),
        (["a.", "b.", "c.", "d."], False),
    ],
)
def test_check_summary(sentences, ok):
    facts = {"techniques_total": 41, "top_gaps": [{"id": "T1621"}]}
    assert (check_summary(sentences, facts) == []) is ok
