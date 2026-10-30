"""Approved hunts as ARM templates for Microsoft Sentinel Repositories. Files only.

Repositories deploys custom content from a connected GitHub or Azure DevOps repository.
Format facts, checked 30 Oct 2026 against learn.microsoft.com/azure/sentinel/ci-cd-custom-content
and Microsoft's sample (github.com/SentinelCICD/RepositoriesSampleContent, Hunting/Sample/ARM):
- a hunting query is a Microsoft.OperationalInsights/workspaces/savedSearches resource
  (API 2020-08-01) in the category "Hunting Queries"
- the template takes one parameter, `workspace`, with no default
- its tags are description, tactics and relevantTechniques, lists comma-separated
- a string that starts with [ and ends with ] is an ARM expression, run at deploy time;
  a literal one starts with [[ instead
- deleting a file from the repository leaves the query in the workspace

The tool writes these files and nothing more. A person commits them to the repository,
and the repository's pipeline deploys them: hunts are never sent to Sentinel from here.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from cti_agent.models import Hunt

FOLDER = "sentinel-hunting"  # under out/<run>/approved/
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
RESOURCE_TYPE = "Microsoft.OperationalInsights/workspaces/savedSearches"
API_VERSION = "2020-08-01"
CATEGORY = "Hunting Queries"
DESCRIPTION_MAX = 240  # where Microsoft's YAML-to-ARM script cuts a description


def query_name(run_id: str, draft_id: str) -> str:
    """The saved search's name. It stays the same for a hunt in a run, so a re-approved
    edit replaces the deployed query, and the same technique from another run doesn't."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cti-to-detection-agent/{run_id}/{draft_id}"))


def sentinel_tactic(shortname: str) -> str:
    """An ATT&CK tactic as Sentinel writes it: command-and-control is CommandAndControl."""
    return "".join(part.capitalize() for part in shortname.split("-"))


def literal(text: str) -> str:
    """Text that ARM keeps as written. A hunt's title comes from a model that read the
    report, and a title in brackets would otherwise run as an expression when deployed."""
    return "[" + text if text.startswith("[") and text.endswith("]") else text


def hunting_template(
    hunt: Hunt,
    approved_kql: str,
    *,
    run_id: str,
    tlp: str,
    approved_by: str,
    approved_at: str,
    tactics: Iterable[str] = (),
) -> dict:
    """The template for one approved hunt. Its query is the approved .kql file, comment
    header and all, under a line that names the TLP and the run."""
    if hunt.lint_failed:
        raise ValueError(f"{hunt.draft_id} fails the lint, so it can't be exported")
    description = f"TLP:{tlp}. Approved by {approved_by} at {approved_at}. Run {run_id}."
    if hunt.retire_when:
        description += f" Retire when: {hunt.retire_when}"
    tags = [("description", _fit(_one_line(description), DESCRIPTION_MAX))]
    names = list(dict.fromkeys(sentinel_tactic(t) for t in tactics))
    if names:
        tags.append(("tactics", ",".join(names)))
    tags.append(("relevantTechniques", hunt.technique_id))
    name = query_name(run_id, hunt.draft_id)
    return {
        "$schema": SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": {"type": "String"}},
        "resources": [
            {
                "type": RESOURCE_TYPE,
                "apiVersion": API_VERSION,
                "name": f"[concat(parameters('workspace'), '/{name}')]",
                "location": "[resourceGroup().location]",
                "properties": {
                    "eTag": "*",
                    "displayName": literal(_one_line(hunt.draft.title)),
                    "category": CATEGORY,
                    "query": literal(f"// TLP:{tlp}. From cti-agent run {run_id}.\n{approved_kql}"),
                    "version": 1,
                    "tags": [{"name": n, "value": literal(v)} for n, v in tags],
                },
            }
        ],
    }


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _fit(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
