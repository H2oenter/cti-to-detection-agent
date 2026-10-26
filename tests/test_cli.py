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


def test_unbuilt_commands_exit_nonzero():
    result = runner.invoke(app, ["review", "some-run"])
    assert result.exit_code == 1
    assert "Not implemented" in result.output


def test_tlp_gate():
    settings = Settings(_env_file=None)
    assert tlp_block_reason("CLEAR", settings) is None
    assert tlp_block_reason("GREEN", settings) is None
    assert "RED" in tlp_block_reason("RED", settings)
    assert tlp_block_reason("AMBER", settings) is not None
    approved = Settings(_env_file=None, endpoint_approved_for_amber=True)
    assert tlp_block_reason("AMBER+STRICT", approved) is None
    assert tlp_block_reason("RED", approved) is not None
