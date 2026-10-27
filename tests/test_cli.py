import pytest
from conftest import FIXTURE_REPORT, FIXTURES, ROOT, FakeModel
from typer.testing import CliRunner

from cti_agent.cli import app
from cti_agent.config import Settings, tlp_block_reason
from cti_agent.llm.client import RecordingClient
from cti_agent.pipeline import run_ingest

runner = CliRunner()


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Run the CLI from an empty folder (no .env) with test paths."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("ATTACK_BUNDLE", str(FIXTURES / "attack-mini.json"))
    monkeypatch.setenv(
        "ATTACK_MOBILE_BUNDLE", str(FIXTURES / "attack-mobile-v20-subset-aa23-320a.json")
    )
    monkeypatch.setenv("ALLOWLIST_FILE", str(ROOT / "data" / "allowlist.txt"))
    return tmp_path


def test_ingest_then_trace_with_replayed_responses(cli_env, settings, attack_index):
    fixtures = cli_env / "llm"
    recording = settings.model_copy(update={"out_dir": cli_env / "recording"})
    run_ingest(
        FIXTURE_REPORT, "CLEAR", recording, RecordingClient(FakeModel(), fixtures),
        attack=attack_index,
    )  # fmt: skip

    result = runner.invoke(app, ["ingest", str(FIXTURE_REPORT), "--replay", str(fixtures)])
    assert result.exit_code == 0, result.output
    assert "complete" in result.output and "Nothing was sent to the API" in result.output
    for reason in ("suspected_injection", "value_not_in_quote", "quote_not_in_source"):
        assert reason in result.output

    [run_dir] = [p for p in (cli_env / "out").iterdir() if p.is_dir()]
    traced = runner.invoke(app, ["trace", run_dir.name])
    assert traced.exit_code == 0, traced.output
    assert "collector" in traced.output and "Budget used" in traced.output


def test_ingest_tlp_red_exits_2(cli_env):
    result = runner.invoke(app, ["ingest", str(FIXTURE_REPORT), "--tlp", "red"])
    assert result.exit_code == 2
    assert "TLP:RED" in result.output


def test_ingest_missing_file_exits_2(cli_env):
    result = runner.invoke(app, ["ingest", "nope.pdf", "--replay", "x"])
    assert result.exit_code == 2


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("ingest", "fetch", "analyse", "review", "publish", "eval", "trace"):
        assert command in result.output


def test_stretch_publish_targets_say_so():
    result = runner.invoke(app, ["publish", "some-run", "--target", "misp"])
    assert result.exit_code == 1
    assert "stretch goal" in result.output


def test_tlp_gate():
    settings = Settings(_env_file=None)
    assert tlp_block_reason("CLEAR", settings) is None
    assert tlp_block_reason("GREEN", settings) is None
    assert "RED" in tlp_block_reason("RED", settings)
    assert tlp_block_reason("AMBER", settings) is not None
    approved = Settings(_env_file=None, endpoint_approved_for_amber=True)
    assert tlp_block_reason("AMBER+STRICT", approved) is None
    assert tlp_block_reason("RED", approved) is not None


def test_analyse_with_replayed_responses(cli_env, settings, aa23_run, aa23_attack, monkeypatch):
    from conftest import AA23_ATTACK, FakeAnalyst

    from cti_agent.pipeline import run_analyse

    monkeypatch.setenv("OUT_DIR", str(settings.out_dir))
    monkeypatch.setenv("ATTACK_BUNDLE", str(AA23_ATTACK[0]))
    monkeypatch.setenv("ATTACK_MOBILE_BUNDLE", str(AA23_ATTACK[1]))
    monkeypatch.setenv("RULES_FILE", str(settings.rules_file))
    monkeypatch.setenv("KQL_SCHEMA_FILE", str(settings.kql_schema_file))
    fixtures = cli_env / "llm-analyse"
    run_analyse(aa23_run, settings, RecordingClient(FakeAnalyst(), fixtures), attack=aa23_attack)

    result = runner.invoke(app, ["analyse", aa23_run, "--replay", str(fixtures), "--force"])
    assert result.exit_code == 0, result.output
    assert "Draft hunts" in result.output and "For leadership" in result.output
    assert "Nothing was sent to the API" in result.output

    again = runner.invoke(app, ["analyse", aa23_run, "--replay", str(fixtures)])
    assert again.exit_code == 2 and "--force" in again.output


def test_analyse_unknown_run_exits_2(cli_env):
    result = runner.invoke(app, ["analyse", "no-such-run", "--replay", "x"])
    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["fetch", "--since", "1w"], "24h"),
        (["fetch", "--source", "kev,twitter"], "unknown source"),
    ],
)
def test_fetch_rejects_bad_options(cli_env, args, message):
    result = runner.invoke(app, args)
    assert result.exit_code == 2 and message in result.output


def test_prepatch_replayed_from_the_cli(cli_env, monkeypatch):
    import json
    from datetime import timedelta

    from conftest import FakeOpener

    from cti_agent.feeds.fetch import run_fetch

    cve = "CVE-2024-4577"
    for key, value in {
        "INBOX_DIR": cli_env / "inbox",
        "SOURCES_FILE": ROOT / "data" / "sources.toml",
        "WATCHLIST_FILE": ROOT / "data" / "watchlist.toml",
        "RULES_FILE": ROOT / "data" / "my_rules.sample.csv",
        "KQL_SCHEMA_FILE": ROOT / "data" / "kql_schema.json",
        "ATTACK_BUNDLE": FIXTURES / "attack-v20-subset-prepatch.json",
    }.items():
        monkeypatch.setenv(key, str(value))
    url = (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/4xxx/"
        + cve
        + ".json"
    )
    raw = (FIXTURES / "feeds" / f"{cve}.json").read_bytes()
    run_fetch(Settings(), since=timedelta(hours=1), sources=(), cve_ids=(cve,),
              opener=FakeOpener({url: json.dumps(json.loads(raw)).encode()}))  # fmt: skip

    result = runner.invoke(
        app, ["prepatch", cve, "--replay", str(FIXTURES / "llm" / f"prepatch-{cve}")]
    )
    assert result.exit_code == 0, result.output
    assert "exposure" in result.output and "behaviour" in result.output
    assert "Retire when PHP is at 8.1.29" in result.output


def test_prepatch_wants_one_id_or_top(cli_env):
    neither = runner.invoke(app, ["prepatch"])
    both = runner.invoke(app, ["prepatch", "CVE-2024-4577", "--top", "3"])
    assert neither.exit_code == both.exit_code == 2
    empty = runner.invoke(app, ["prepatch", "--top", "3", "--yes"])
    assert empty.exit_code == 0 and "Nothing new to hunt" in empty.output


@pytest.fixture
def analysed_run(cli_env, settings, aa23_run, aa23_attack, monkeypatch):
    """AA23-320A ingested and analysed (fake models), with the CLI pointed at it."""
    from conftest import AA23_ATTACK, FakeAnalyst

    from cti_agent.pipeline import run_analyse

    run_analyse(aa23_run, settings, FakeAnalyst(bad_query_for={"T1204"}), attack=aa23_attack)
    for key, value in {
        "OUT_DIR": settings.out_dir,
        "ATTACK_BUNDLE": AA23_ATTACK[0],
        "ATTACK_MOBILE_BUNDLE": AA23_ATTACK[1],
        "KQL_SCHEMA_FILE": settings.kql_schema_file,
        "CTI_AGENT_REVIEWER": "sam",
    }.items():
        monkeypatch.setenv(key, str(value))
    return aa23_run


def test_review_one_item_then_show_the_audit(analysed_run, settings):
    from cti_agent.audit import AuditLog
    from cti_agent.stages.gate import Gate

    gate = Gate(settings, analysed_run, "x", AuditLog(settings.out_dir / "audit.jsonl"))
    first = gate.items[0].ref
    ok = runner.invoke(app, ["review", analysed_run, "--item", first, "--approve"])
    assert ok.exit_code == 0, ok.output
    assert "approved by sam" in ok.output
    missing_reason = runner.invoke(app, ["review", analysed_run, "--item", first, "--reject"])
    assert missing_reason.exit_code == 2 and "reason" in missing_reason.output

    shown = runner.invoke(app, ["audit", "--run", analysed_run, "--verify"])
    assert shown.exit_code == 0 and "Hash chain verified" in shown.output and "sam" in shown.output


def test_interactive_session(analysed_run, settings, monkeypatch):
    """Approve a hunt, reject one with a reason, fail to approve the lint-failed one,
    edit it, approve it, then approve every remaining attack-pattern in one go."""
    import click

    fixed = (
        'DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where FileName =~ "mshta.exe"\n'
        "| project Timestamp, DeviceName, ProcessCommandLine"
    )
    monkeypatch.setattr(click, "edit", lambda text, extension=None: fixed)
    keys = "\n".join([
        "a",                    # T1199 approve
        "a", "e", "a",          # T1204: approve refused (lint), edit, then approve
        "r", "too noisy here",  # T1648 reject with reason
        "s", "s",               # skip the other two hunts
        "a",                    # threat actor
        "A",                    # every attack-pattern
    ]) + "\n"  # fmt: skip
    result = runner.invoke(app, ["review", analysed_run], input=keys)
    assert result.exit_code == 0, result.output
    assert "lint errors" in result.output and "Edit saved and logged" in result.output
    assert "41 attack-pattern items: approved" in result.output

    from cti_agent.audit import AuditLog

    rows = AuditLog(settings.out_dir / "audit.jsonl").entries(analysed_run)
    decisions = [(r["action"], r["decision"]) for r in rows]
    assert decisions[:4] == [("review", "approve"), ("edit", None), ("review", "approve"),
                             ("review", "reject")]  # fmt: skip
    assert sum(r["bulk"] for r in rows) == 41
    approved = settings.out_dir / analysed_run / "approved"
    assert len(list((approved / "hunts").glob("*.kql"))) == 2
    assert (approved / "stix-bundle.json").exists()


def test_tampered_audit_log_blocks_review(analysed_run, settings):
    first_item = runner.invoke(app, ["review", analysed_run, "--all"], input="a\nq\n")
    assert first_item.exit_code == 0
    log = settings.out_dir / "audit.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace('"approve"', '"reject"'), "utf-8")
    blocked = runner.invoke(app, ["review", analysed_run])
    assert blocked.exit_code == 4 and "failed verification" in blocked.output
    assert runner.invoke(app, ["audit", "--verify"]).exit_code == 4
