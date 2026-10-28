"""publish: what qualifies, how it's batched, the dry run, and --apply against a fake API."""

import json
import sqlite3
import sys
from datetime import UTC, datetime

import pytest
import stix2
from conftest import FIXTURE_REPORT, FIXTURES, ROOT, FakeModel
from typer.testing import CliRunner

from cti_agent import publishing
from cti_agent.audit import AuditLog
from cti_agent.cli import app
from cti_agent.outputs import sentinel_upload
from cti_agent.outputs.sentinel_upload import (
    PublishError,
    PublishPlan,
    endpoint,
    plan_sentinel,
    send,
    urllib_post,
    write_dry_run,
)
from cti_agent.pipeline import run_ingest
from cti_agent.stages.gate import Gate

WORKSPACE = "11111111-2222-3333-4444-555555555555"
runner = CliRunner()


@pytest.fixture
def run_id(settings, attack_index):
    return run_ingest(FIXTURE_REPORT, "CLEAR", settings, FakeModel(), attack=attack_index).run_id


def gate_for(settings, run_id):
    return Gate(
        settings, run_id, "sam", AuditLog(settings.out_dir / "audit.jsonl", settings.db_path)
    )


def approve_all(gate, except_kinds=()):
    for item in list(gate.items):
        if item.kind not in except_kinds:
            gate.decide(gate.item(item.ref), "approve")


def tamper(settings, run_id, kind, **changes):
    with sqlite3.connect(settings.db_path) as conn:
        stix_id, raw = conn.execute(
            "SELECT stix_id, json FROM objects WHERE run_id = ? AND type = ?", (run_id, kind)
        ).fetchone()
        conn.execute(
            "UPDATE objects SET json = ? WHERE run_id = ? AND stix_id = ?",
            (json.dumps({**json.loads(raw), **changes}), run_id, stix_id),
        )
    return stix_id


# --- what qualifies -----------------------------------------------------------------------


def test_plan_keeps_what_sentinel_accepts(settings, run_id):
    gate = gate_for(settings, run_id)
    approve_all(gate)
    plan = plan_sentinel(gate)

    assert plan.counts() == {
        "identity": 1, "indicator": 4, "threat-actor": 1, "attack-pattern": 3, "relationship": 7
    }  # fmt: skip
    assert [s["type"] for s in plan.skipped] == ["vulnerability"]
    assert plan.objects[0]["type"] == "identity"  # created_by_ref target goes first
    ids = {o["id"] for o in plan.objects}
    assert all(o["source_ref"] in ids and o["target_ref"] in ids
               for o in plan.objects if o["type"] == "relationship")  # fmt: skip


def test_rejected_items_and_their_links_stay_out(settings, run_id):
    gate = gate_for(settings, run_id)
    indicator = next(i for i in gate.items if i.kind == "indicator")
    gate.decide(indicator, "reject", reason="sinkholed")
    approve_all(gate, except_kinds=("indicator",))
    plan = plan_sentinel(gate)
    assert indicator.stix["id"] not in {o["id"] for o in plan.objects}
    assert plan.counts()["indicator"] == 0 and plan.counts()["relationship"] == 3


def test_nothing_approved_means_nothing_to_publish(settings, run_id):
    with pytest.raises(PublishError, match="no approved STIX"):
        plan_sentinel(gate_for(settings, run_id))


def test_a_change_after_approval_blocks_everything(settings, run_id):
    approve_all(gate_for(settings, run_id))
    tamper(settings, run_id, "indicator", description="quietly changed in the database")
    with pytest.raises(PublishError, match="changed after they were approved"):
        plan_sentinel(gate_for(settings, run_id))


def test_tlp_red_is_never_published(settings, run_id):
    tamper(settings, run_id, "indicator", x_cti_agent_tlp="RED")
    gate = gate_for(settings, run_id)
    approve_all(gate)
    with pytest.raises(PublishError, match="TLP:RED"):
        plan_sentinel(gate)


# --- batching and the dry run --------------------------------------------------------------


def test_batches_of_at_most_100():
    plan = PublishPlan("r", [{"id": f"indicator--{i}", "type": "indicator"} for i in range(250)])
    assert [len(b) for b in plan.batches] == [100, 100, 50]


def test_dry_run_writes_valid_requests_and_sends_nothing(settings, run_id, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("the dry run must not touch the network")

    monkeypatch.setattr(sentinel_upload, "urllib_post", no_network)
    gate = gate_for(settings, run_id)
    approve_all(gate)
    folder = write_dry_run(plan_sentinel(gate), gate.out_dir, None, datetime.now(UTC))

    body = json.loads((folder / "request-001.json").read_text(encoding="utf-8"))
    assert body["sourcesystem"] == "cti-to-detection-agent"
    for obj in body["stixobjects"]:
        stix2.parse(json.dumps(obj), allow_custom=True)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert "<SENTINEL_WORKSPACE_ID>" in manifest["url"] and "nothing was sent" in manifest["mode"]
    assert "never written" in manifest["headers"]["Authorization"]
    assert manifest["skipped"][0]["type"] == "vulnerability"


def test_two_dry_runs_in_the_same_second_get_their_own_folders(settings, run_id):
    gate = gate_for(settings, run_id)
    approve_all(gate)
    now = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
    first = write_dry_run(plan_sentinel(gate), gate.out_dir, None, now)
    second = write_dry_run(plan_sentinel(gate), gate.out_dir, None, now)
    assert first != second and second.name == first.name + "-2"


# --- --apply against a fake API -------------------------------------------------------------


def test_an_upload_sends_only_the_plan_that_was_confirmed(settings, run_id, monkeypatch):
    gate = gate_for(settings, run_id)
    approve_all(gate, except_kinds=("attack-pattern",))
    log = gate.audit
    confirmed = publishing.dry_run(gate, settings, log).digest
    pattern = next(i for i in gate.items if i.kind == "attack-pattern")
    gate.decide(pattern, "approve")  # approvals change after the dry run
    api = FakeSentinel([(200, {}, b"")])
    monkeypatch.setattr(sentinel_upload, "urllib_post", api)
    workspace = settings.model_copy(update={"sentinel_workspace_id": WORKSPACE})

    with pytest.raises(PublishError, match="changed since you confirmed"):
        publishing.upload(gate, workspace, log, lambda: "tok", expected_digest=confirmed)
    assert api.calls == []
    fresh = publishing.dry_run(gate, settings, log).digest
    sent = publishing.upload(gate, workspace, log, lambda: "tok", expected_digest=fresh)
    assert len(api.calls) == 1 and sent.failed == []
    assert [r["decision"] for r in log.entries(run_id) if r["action"] == "publish"] == [
        "dry-run", "dry-run", "applied"
    ]  # fmt: skip


class FakeSentinel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, body, headers):
        self.calls.append((url, json.loads(body), headers))
        return self.responses.pop(0)


def small_plan(n=3):
    return PublishPlan("r", [{"id": f"indicator--{i}", "type": "indicator"} for i in range(n)])


def test_429_waits_as_told_then_reads_per_object_errors():
    errors = {"errors": [{"recordIndex": 1, "errorMessages": ["Invalid pattern"]}]}
    throttled = b'{"statusCode":429,"message":"Rate limit is exceeded. Try again in 3 seconds."}'
    api = FakeSentinel([(429, {}, throttled), (200, {}, json.dumps(errors).encode())])
    waits, tokens = [], []
    results = send(small_plan(), WORKSPACE, lambda: tokens.append(1) or "tok",
                   post=api, sleep=waits.append)  # fmt: skip
    assert waits == [3.0] and len(tokens) == 2
    [result] = results
    assert result.attempts == 2
    assert result.failed == [{"id": "indicator--1", "type": "indicator",
                              "messages": ["Invalid pattern"]}]  # fmt: skip
    url, body, headers = api.calls[0]
    assert url == endpoint(WORKSPACE) and body["sourcesystem"] == "cti-to-detection-agent"
    assert headers["Authorization"] == "Bearer tok"


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_hard_errors_stop_the_upload(status):
    with pytest.raises(PublishError, match=f"HTTP {status}"):
        send(small_plan(), WORKSPACE, lambda: "tok", post=FakeSentinel([(status, {}, b"no")]))


def test_server_errors_are_retried_then_given_up_on():
    api = FakeSentinel([(503, {"Retry-After": "1"}, b"")] * sentinel_upload.MAX_ATTEMPTS)
    with pytest.raises(PublishError, match="still HTTP 503"):
        send(small_plan(), WORKSPACE, lambda: "tok", post=api, sleep=lambda s: None)


@pytest.mark.parametrize("bad", ["", "not-a-guid", "../../evil"])
def test_workspace_id_must_be_a_guid(bad):
    with pytest.raises(PublishError, match="GUID"):
        endpoint(bad)


def test_only_the_sentinel_host_is_ever_posted_to():
    with pytest.raises(PublishError, match="refusing"):
        urllib_post("https://evil.example/upload", b"{}", {})


# --- through the CLI ------------------------------------------------------------------------


@pytest.fixture
def cli_run(run_id, settings, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no .env here
    for key, value in {
        "OUT_DIR": settings.out_dir,
        "KQL_SCHEMA_FILE": ROOT / "data" / "kql_schema.json",
        "ATTACK_BUNDLE": FIXTURES / "attack-mini.json",
        "CTI_AGENT_REVIEWER": "sam",
        "COLUMNS": "200",
    }.items():
        monkeypatch.setenv(key, str(value))
    approve_all(gate_for(settings, run_id))
    return run_id


def test_cli_dry_run(cli_run, settings):
    result = runner.invoke(app, ["publish", cli_run])
    assert result.exit_code == 0, result.output
    assert "Dry run: nothing was sent" in result.output and "vulnerability" in result.output
    last = AuditLog(settings.out_dir / "audit.jsonl").entries(cli_run)[-1]
    assert (last["action"], last["decision"]) == ("publish", "dry-run")


@pytest.mark.parametrize(
    ("env", "args", "message"),
    [
        ({}, [], "needs SENTINEL_WORKSPACE_ID"),
        ({"SENTINEL_WORKSPACE_ID": WORKSPACE}, [], "choose the publishing identity explicitly"),
    ],
)
def test_cli_apply_needs_a_workspace_and_an_explicit_identity(cli_run, monkeypatch, env, args,
                                                              message):  # fmt: skip
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    result = runner.invoke(app, ["publish", cli_run, "--apply", "--yes", *args])
    assert result.exit_code == 2 and message in result.output


def test_without_azure_identity_installed_the_messages_still_guide(cli_run, monkeypatch):
    """CI installs only the dev extras. A missing identity choice is still reported as that,
    and the install hint keeps its [azure] (rich used to read it as a style tag)."""
    monkeypatch.setitem(sys.modules, "azure.identity", None)  # import now fails
    monkeypatch.setenv("SENTINEL_WORKSPACE_ID", WORKSPACE)
    unchosen = runner.invoke(app, ["publish", cli_run, "--apply", "--yes"])
    assert unchosen.exit_code == 2
    assert "choose the publishing identity explicitly" in unchosen.output
    for key in ("PUBLISH_AZURE_TENANT_ID", "PUBLISH_AZURE_CLIENT_ID"):
        monkeypatch.setenv(key, "00000000-0000-0000-0000-000000000000")
    monkeypatch.setenv("PUBLISH_AZURE_CLIENT_SECRET", "test-secret-not-real")
    missing = runner.invoke(app, ["publish", cli_run, "--apply", "--yes"])
    assert missing.exit_code == 2
    assert 'pip install -e ".[azure]"' in missing.output


def test_cli_apply_uploads_audits_and_never_writes_the_token(cli_run, settings, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE_ID", WORKSPACE)
    monkeypatch.setattr("cti_agent.cli.token_provider", lambda s, az: lambda: "SECRET-TOKEN")
    api = FakeSentinel([(200, {}, b"")])
    monkeypatch.setattr(sentinel_upload, "urllib_post", api)

    result = runner.invoke(app, ["publish", cli_run, "--apply", "--yes"])
    assert result.exit_code == 0, result.output
    assert len(api.calls) == 1 and api.calls[0][2]["Authorization"] == "Bearer SECRET-TOKEN"

    rows = AuditLog(settings.out_dir / "audit.jsonl").entries(cli_run)
    assert [r["decision"] for r in rows if r["action"].startswith("publish")] == [
        "sent", "applied"
    ]  # fmt: skip
    files = [p for p in settings.out_dir.rglob("*") if p.is_file() and p.suffix != ".db"]
    written = "".join(p.read_text(encoding="utf-8", errors="ignore") for p in files)
    assert "SECRET-TOKEN" not in written
    with sqlite3.connect(settings.db_path) as conn:
        statuses = {s for (s,) in conn.execute(
            "SELECT review_status FROM objects WHERE run_id = ? AND type = 'indicator'", (cli_run,)
        )}  # fmt: skip
    assert statuses == {"published"}


def test_cli_apply_can_be_declined(cli_run, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE_ID", WORKSPACE)
    monkeypatch.setattr("cti_agent.cli.token_provider", lambda s, az: lambda: "tok")
    api = FakeSentinel([])
    monkeypatch.setattr(sentinel_upload, "urllib_post", api)
    result = runner.invoke(app, ["publish", cli_run, "--apply"], input="n\n")
    assert result.exit_code == 1 and api.calls == []
