from typer.testing import CliRunner

from cti_agent.cli import app
from cti_agent.config import Settings, tlp_block_reason

runner = CliRunner()


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
