"""Guided labelling: scripted sessions through a small draft, and the script end to end."""

import importlib.util
import io
import json
import sys
from datetime import date

import pytest
from conftest import FIXTURES, ROOT
from rich.console import Console

from cti_agent.evaluation.candidates import draft, finish_draft
from cti_agent.evaluation.gold import load_gold
from cti_agent.evaluation.labelling import candidates, run_labelling
from cti_agent.inputs import load_source

TEXT = (
    "C2 at 198.51.101[.]7 and update-portal-fixture[.]net.\n"
    "Their portals mimicked targetsname-sso.com.\n"
    "Actors used T1219 and T1566.004, and exploited CVE-2024-55591.\n"
)
# What the labeller decides for each candidate, by value.
DECIDE = {
    "198.51.101.7": "g",  # in the text and CISA's STIX
    "update-portal-fixture.net": "o",
    "targetsname-sso.com": "x",  # a naming-pattern placeholder
    "T1219": "o",  # a tool's capability
    "T1566.004": "g",
    "CVE-2024-55591": "g",
}
METADATA = {
    "Report title": "Fixture advisory",
    "Advisory URL": "https://www.cisa.gov/fixture",
    "Actors": "Fixture Lynx, Lynx Two",
    "Labelled by": "Samuel Omiwole",
}


@pytest.fixture
def draft_path(tmp_path):
    (tmp_path / "reports").mkdir()
    report = tmp_path / "reports" / "fx.txt"
    report.write_text(TEXT, encoding="utf-8")
    stix = tmp_path / "reports" / "fx-stix.json"
    stix.write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.101.7']"},
        {"type": "domain-name", "value": "only-in-stix-fixture.net"},
    ]}), encoding="utf-8")  # fmt: skip
    path = tmp_path / "fx.draft.json"
    path.write_text(json.dumps(draft(load_source(report), "fx", stix)), encoding="utf-8")
    return path


class Labeller:
    """Answers by value, with any extra keys (back, skip, stop) queued up front."""

    def __init__(self, path, extra=(), metadata=None):
        self.order = [c.value for c in candidates(json.loads(path.read_text("utf-8")))]
        self.keys = list(extra)
        self.asked, self.prompts = 0, []
        self.metadata = METADATA if metadata is None else metadata

    def script(self, *values):
        self.keys += [DECIDE[v] for v in values]
        return self

    def ask(self, menu, keys):
        self.asked += 1
        key = self.keys.pop(0)
        assert key in keys, (key, keys)
        return key

    def ask_text(self, prompt, default):
        self.prompts.append(prompt)
        return next((v for p, v in self.metadata.items() if prompt.startswith(p)), default)


def session(path, labeller, **kwargs):
    out = io.StringIO()
    result = run_labelling(path, Console(file=out, width=120), ask=labeller.ask,
                           ask_text=labeller.ask_text, today=date(2026, 11, 2),
                           names={"T1566.004": "Spearphishing Voice"}.get, **kwargs)  # fmt: skip
    return result, out.getvalue()


def test_a_full_session_writes_the_gold_file_the_eval_loads(draft_path):
    first, second, *rest = Labeller(draft_path).order
    labeller = Labeller(draft_path).script(first, second)
    labeller.keys += ["b"]  # go back and look at the second one again
    labeller.script(second, *rest)
    result, shown = session(draft_path, labeller)

    assert result.complete and result.decided == 6
    assert "also in CISA's STIX" in shown and "1 values only in CISA's STIX" in shown
    assert "Spearphishing Voice" in shown and "page 1" in shown
    done = finish_draft(draft_path)
    assert done.notes == []
    [gold] = load_gold(draft_path.parent)
    assert [i.value for i in gold.indicators] == ["198.51.101.7"]
    assert [i.value for i in gold.optional_indicators] == ["update-portal-fixture.net"]
    assert (gold.techniques, gold.optional_techniques) == (["T1566.004"], ["T1219"])
    assert gold.cves == ["CVE-2024-55591"]
    assert gold.actors == ["Fixture Lynx", "Lynx Two"] and gold.labelled_on == "2026-11-02"


def test_stopping_saves_and_the_next_run_carries_on(draft_path):
    order = Labeller(draft_path).order
    labeller = Labeller(draft_path).script(order[0])
    labeller.keys += ["q"]
    stopped, _ = session(draft_path, labeller)
    assert stopped.stopped and stopped.decided == 1 and labeller.prompts == []
    saved = json.loads(draft_path.read_text(encoding="utf-8"))
    assert saved["labelling"]["decisions"] == {"indicator:ipv4:198.51.101.7": "gold"}

    again = Labeller(draft_path).script(*order[1:])
    resumed, shown = session(draft_path, again)
    assert resumed.complete and again.asked == 5 and "1 already decided" in shown


def test_skipping_leaves_it_undecided_and_saves_no_gold_file(draft_path):
    order = Labeller(draft_path).order
    labeller = Labeller(draft_path, extra=["s"]).script(*order[1:])
    result, shown = session(draft_path, labeller)
    assert not result.complete and result.undecided == 1
    assert labeller.prompts == [] and "1 candidates still to decide" in shown


def test_entries_added_by_hand_survive_and_all_shows_decisions_again(draft_path):
    drafted = json.loads(draft_path.read_text(encoding="utf-8"))
    drafted["gold"]["indicators"].append({"kind": "ipv4", "value": "203.0.113.9"})
    draft_path.write_text(json.dumps(drafted), encoding="utf-8")
    order = Labeller(draft_path).order
    session(draft_path, Labeller(draft_path).script(*order))

    again = Labeller(draft_path).script(*order)
    _, shown = session(draft_path, again, include_decided=True)
    assert again.asked == 6 and "now: gold" in shown
    gold = json.loads(draft_path.read_text(encoding="utf-8"))["gold"]
    assert {"kind": "ipv4", "value": "203.0.113.9"} in gold["indicators"]
    assert len(gold["indicators"]) == 2  # the hand-added one and 198.51.101.7, not twice


def test_the_script_end_to_end(tmp_path, monkeypatch, capsys):
    """Start a draft, refuse to overwrite it once it holds decisions, label it from the
    keyboard (a wrong key included), and save the gold file."""
    spec = importlib.util.spec_from_file_location("gold_draft", ROOT / "scripts" / "gold_draft.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    monkeypatch.setenv("ATTACK_BUNDLE", str(FIXTURES / "attack-mini.json"))
    report = tmp_path / "fx.txt"
    report.write_text(TEXT, encoding="utf-8")

    def run(*args, keys=()):
        monkeypatch.setattr(sys, "argv", ["gold_draft.py", *map(str, args)])
        typed = iter(keys)
        monkeypatch.setattr("builtins.input", lambda prompt="": next(typed))
        code = script.main()
        return code, capsys.readouterr()

    assert run(report, "--out", tmp_path)[0] == 0
    path = tmp_path / "fx.draft.json"
    order = [c.value for c in candidates(json.loads(path.read_text("utf-8")))]
    code, shown = run("--label", path, keys=["z", DECIDE[order[0]], "q"])
    assert code == 0 and "Press one of" in shown.out

    code, shown = run(report, "--out", tmp_path)
    assert code == 1 and "already holds labelling decisions" in shown.err

    meta = ["Fixture advisory", "https://www.cisa.gov/fixture", "Fixture Lynx", "Samuel Omiwole",
            "", ""]  # fmt: skip
    code, shown = run("--label", path, keys=[DECIDE[v] for v in order[1:]] + meta)
    assert code == 0, shown.err
    assert "Saved" in shown.out and (tmp_path / "fx.json").exists()
