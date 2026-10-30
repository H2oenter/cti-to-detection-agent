"""Approved hunts as Sentinel Repositories templates: the shape of Microsoft's sample,
exactly what is approved, the run's TLP, and nothing a deploy would run as an expression."""

import json
import sqlite3
import uuid
from contextlib import closing

import pytest
from conftest import FakeAnalyst

from cti_agent.audit import AuditLog
from cti_agent.models import Confidence, Hunt, HuntDraft, LintFinding
from cti_agent.outputs.sentinel_hunting import (
    DESCRIPTION_MAX,
    hunting_template,
    literal,
    query_name,
    sentinel_tactic,
)
from cti_agent.pipeline import run_analyse
from cti_agent.stages.gate import Gate

RUN = "20261030T115927Z-2fa56304-8ac2"
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
CLEAN_QUERY = """DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe" and FileName =~ "mshta.exe"
| project Timestamp, DeviceName, ProcessCommandLine"""


def make_hunt(title="WMIC shadow copy deletion via WMI", **changes) -> Hunt:
    draft = HuntDraft(
        title=title, technique_id="T1047", tables=["DeviceProcessEvents"], query=CLEAN_QUERY,
        evidence_quotes=["The actors used WMIC to delete shadow copies."],
        expected_false_positives=["Backup software"], tuning_notes="", assumptions=[],
        confidence=Confidence(score=70, rationale="A specific command line."),
    )  # fmt: skip
    return Hunt(draft_id="T1047-coverage-gap", kind="coverage_gap", technique_id="T1047",
                draft=draft, item_hash="sha256:abc", model="m", prompt_version="analyst@v1",
                **changes)  # fmt: skip


def template_for(hunt, tactics=("execution",)):
    return hunting_template(hunt, "// APPROVED by sam\nquery\n", run_id=RUN, tlp="CLEAR",
                            approved_by="sam", approved_at="2026-10-30T12:15:14+00:00",
                            tactics=tactics)  # fmt: skip


def props(template):
    return template["resources"][0]["properties"]


def test_the_template_has_the_shape_of_microsofts_sample():
    """Pinned to Microsoft's Repositories sample (Hunting/Sample/ARM): one saved search in
    the "Hunting Queries" category, and a workspace parameter that the deployment fills in."""
    template = template_for(make_hunt())
    assert template["$schema"] == SCHEMA and template["contentVersion"] == "1.0.0.0"
    assert template["parameters"] == {"workspace": {"type": "String"}}
    (resource,) = template["resources"]
    assert resource["type"] == "Microsoft.OperationalInsights/workspaces/savedSearches"
    assert resource["apiVersion"] == "2020-08-01"
    name = query_name(RUN, "T1047-coverage-gap")
    assert resource["name"] == f"[concat(parameters('workspace'), '/{name}')]"
    assert resource["location"] == "[resourceGroup().location]"
    p = resource["properties"]
    assert set(p) == {"eTag", "displayName", "category", "query", "version", "tags"}
    assert (p["eTag"], p["category"], p["version"]) == ("*", "Hunting Queries", 1)
    assert [t["name"] for t in p["tags"]] == ["description", "tactics", "relevantTechniques"]
    assert p["tags"][1:] == [
        {"name": "tactics", "value": "Execution"},
        {"name": "relevantTechniques", "value": "T1047"},
    ]


def test_tactics_are_named_the_way_sentinel_names_them():
    assert sentinel_tactic("command-and-control") == "CommandAndControl"
    assert sentinel_tactic("initial-access") == "InitialAccess"
    tags = props(template_for(make_hunt(), ("persistence", "initial-access", "persistence")))
    assert tags["tags"][1] == {"name": "tactics", "value": "Persistence,InitialAccess"}
    # A pre-patch run stores no attack patterns, so its templates name the technique alone.
    tags = props(template_for(make_hunt(), ()))["tags"]
    assert [t["name"] for t in tags] == ["description", "relevantTechniques"]


def test_a_title_in_brackets_reaches_sentinel_as_text():
    """ARM runs a string that starts with [ and ends with ] as an expression when it
    deploys. A model writes the title after reading a report, so a title built to copy a
    storage key into the query's name must stay text."""
    title = "[listKeys(resourceId('Microsoft.Storage/storageAccounts', 'logs'), '2023-01-01')]"
    assert props(template_for(make_hunt(title)))["displayName"] == "[" + title
    assert literal("[T1047] WMI use") == "[T1047] WMI use"  # not an expression, left alone
    assert literal("[[x]") == "[[[x]"  # ARM drops the first bracket and keeps [[x]


def test_the_name_stays_the_same_for_a_hunt_in_a_run():
    """So a re-approved edit replaces the deployed query, and another run's hunt for the
    same technique doesn't overwrite it."""
    name = query_name(RUN, "T1047-coverage-gap")
    assert str(uuid.UUID(name)) == name == query_name(RUN, "T1047-coverage-gap")
    assert name != query_name("20261027T192916Z-9ed0ff84-19de", "T1047-coverage-gap")


def test_the_description_leads_with_the_tlp_and_the_approval_and_fits():
    hunt = make_hunt(retire_when="When every internet-facing host runs a fixed version. " * 8)
    description = props(template_for(hunt))["tags"][0]["value"]
    assert description.startswith(f"TLP:CLEAR. Approved by sam at 2026-10-30T12:15:14+00:00. Run {RUN}. Retire when: ")  # noqa: E501  # fmt: skip
    assert len(description) == DESCRIPTION_MAX and description.endswith("…")


def test_a_hunt_that_fails_the_lint_is_never_exported():
    hunt = make_hunt(lint=[LintFinding(severity="error", code="external_data", message="no")])
    with pytest.raises(ValueError, match="lint"):
        template_for(hunt)


# --- written by the gate -----------------------------------------------------------------


@pytest.fixture
def gate(settings, aa23_run, aa23_attack):
    """AA23-320A analysed with fake models; the T1204 draft fails the lint."""
    run_analyse(aa23_run, settings, FakeAnalyst(bad_query_for={"T1204"}), attack=aa23_attack)
    return Gate(settings, aa23_run, "sam", AuditLog(settings.out_dir / "audit.jsonl",
                                                    settings.db_path))  # fmt: skip


def hunt_for(gate, technique):
    return next(i for i in gate.items if i.kind == "hunt" and i.hunt.technique_id == technique)


def test_each_approved_hunt_gets_a_template_and_nothing_else_does(gate):
    approved = hunt_for(gate, "T1199")
    rejected = next(i for i in gate.items if i.kind == "hunt" and i is not approved)
    gate.decide(approved, "approve")
    gate.decide(rejected, "reject", reason="too broad for this environment")

    folder = gate.out_dir / "approved" / "sentinel-hunting"
    assert [p.name for p in folder.iterdir()] == ["T1199-coverage-gap.json"]
    p = props(json.loads((folder / "T1199-coverage-gap.json").read_text(encoding="utf-8")))
    kql = gate.out_dir / "approved" / "hunts" / "T1199-coverage-gap.kql"
    # The query is the approved .kql file as written, under a line naming the TLP and run.
    assert p["query"] == f"// TLP:CLEAR. From cti-agent run {gate.run_id}.\n" + kql.read_text(
        encoding="utf-8"
    )
    assert p["query"].splitlines()[1].startswith("// APPROVED by sam at ")
    assert p["displayName"] == "Hunt for T1199"
    assert p["tags"][0]["value"].startswith("TLP:CLEAR. Approved by sam at ")
    # The tactic comes from the run's own attack pattern for T1199 (Trusted Relationship).
    assert p["tags"][1:] == [
        {"name": "tactics", "value": "InitialAccess"},
        {"name": "relevantTechniques", "value": "T1199"},
    ]

    gate.edit_hunt(approved, CLEAN_QUERY)  # an edit needs a new decision; until then, no file
    assert not list(folder.iterdir())


@pytest.mark.parametrize(("tlp", "exported"), [("AMBER+STRICT", True), ("RED", False)])
def test_templates_follow_the_runs_tlp(gate, settings, tlp, exported):
    """A template is made to be shared, through a repository and then a workspace, so it
    carries the run's TLP, and a TLP:RED run gets none. Its .kql files stay local."""
    with closing(sqlite3.connect(settings.db_path)) as conn, conn:
        conn.execute("UPDATE runs SET tlp = ? WHERE run_id = ?", (tlp, gate.run_id))
    marked = Gate(settings, gate.run_id, "sam", gate.audit)
    marked.decide(hunt_for(marked, "T1199"), "approve")

    assert (marked.out_dir / "approved" / "hunts" / "T1199-coverage-gap.kql").exists()
    path = marked.out_dir / "approved" / "sentinel-hunting" / "T1199-coverage-gap.json"
    assert path.exists() is exported
    if exported:
        p = props(json.loads(path.read_text(encoding="utf-8")))
        assert p["query"].startswith(f"// TLP:{tlp}. From cti-agent run ")
        assert p["tags"][0]["value"].startswith(f"TLP:{tlp}. Approved by sam")
