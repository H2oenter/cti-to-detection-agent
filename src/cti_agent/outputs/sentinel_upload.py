"""Payloads for Microsoft Sentinel's STIX objects upload API. A dry run unless --apply.

API facts, checked 27 Oct 2026 against learn.microsoft.com/azure/sentinel/stix-objects-api
(the API is in preview):
- POST .../workspaces/{id}/threat-intelligence-stix-objects:upload, body
  {"sourcesystem": ..., "stixobjects": [...]}; "Microsoft Sentinel" is a reserved source name
- accepted types: indicator, attack-pattern, threat-actor, identity, relationship
- at most 100 objects per request and 100 requests a minute; a 429 says how long to wait
- a 200 can still list per-object errors by recordIndex
- token audience https://management.azure.com; the caller needs Microsoft Sentinel
  Contributor on the workspace (the only write role in this design, on its own identity)
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from cti_agent.config import Settings
from cti_agent.feeds.http import _AllowlistRedirects
from cti_agent.outputs.stix_out import TOOL_IDENTITY
from cti_agent.stages.gate import Gate

API_VERSION = "2024-02-01-preview"
HOST = "api.ti.sentinel.azure.com"
ENDPOINT = (
    f"https://{HOST}/workspaces/{{workspace}}/threat-intelligence-stix-objects:upload"
    f"?api-version={API_VERSION}"
)
TOKEN_SCOPE = "https://management.azure.com/.default"
SOURCE_SYSTEM = "cti-to-detection-agent"
ACCEPTED_TYPES = {"indicator", "attack-pattern", "threat-actor", "identity", "relationship"}
BATCH_SIZE = 100
MAX_ATTEMPTS = 6
MAX_WAIT_SECONDS = 120
_GUID = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")

Post = Callable[[str, bytes, dict], tuple[int, dict, bytes]]


class PublishError(Exception):
    pass


@dataclass
class PublishPlan:
    run_id: str
    objects: list[dict]
    skipped: list[dict] = field(default_factory=list)
    hunts_not_uploaded: int = 0

    @property
    def batches(self) -> list[list[dict]]:
        return [self.objects[i : i + BATCH_SIZE] for i in range(0, len(self.objects), BATCH_SIZE)]

    def counts(self) -> Counter:
        return Counter(o["type"] for o in self.objects)


@dataclass
class BatchResult:
    index: int  # 1-based
    status: int
    attempts: int
    object_ids: list[str]
    failed: list[dict] = field(default_factory=list)  # {"id", "type", "messages"}


def plan_sentinel(gate: Gate) -> PublishPlan:
    """Approved, unchanged STIX objects in an order Sentinel accepts. Fails closed."""
    latest = gate.audit.latest_decisions(gate.run_id)
    changed = [
        i.ref
        for i in gate.items
        if (decision := latest.get(i.ref))
        and decision["decision"] == "approve"
        and decision["item_hash"] != i.hash
    ]
    if changed:
        raise PublishError(
            "these items changed after they were approved, so nothing is published until "
            f"they're reviewed again: {', '.join(changed)}"
        )
    approved = [i.stix for i in gate.approved() if i.stix]
    if not approved:
        raise PublishError(f"run {gate.run_id} has no approved STIX objects to publish")
    red = [o["id"] for o in approved if o.get("x_cti_agent_tlp") == "RED"]
    if red:
        raise PublishError(f"TLP:RED objects are never published: {', '.join(red)}")

    entities, skipped = [], []
    for obj in approved:
        if obj["type"] in ACCEPTED_TYPES:
            entities.append(obj)
        else:
            skipped.append(
                {"id": obj["id"], "type": obj["type"],
                 "reason": f"Sentinel's upload API doesn't accept {obj['type']} objects"}
            )  # fmt: skip
    ids = {o["id"] for o in entities}
    relationships = [
        o for o in gate.run_objects()
        if o["type"] == "relationship" and o["source_ref"] in ids and o["target_ref"] in ids
    ]  # fmt: skip
    identity = (
        [json.loads(TOOL_IDENTITY.serialize())]
        if any(o.get("created_by_ref") == TOOL_IDENTITY.id for o in entities)
        else []
    )
    return PublishPlan(
        run_id=gate.run_id,
        objects=[*identity, *entities, *relationships],
        skipped=skipped,
        hunts_not_uploaded=sum(1 for i in gate.approved() if i.hunt),
    )


def request_body(batch: list[dict]) -> dict:
    return {"sourcesystem": SOURCE_SYSTEM, "stixobjects": batch}


def endpoint(workspace_id: str) -> str:
    if not _GUID.match(workspace_id or ""):
        raise PublishError(f"SENTINEL_WORKSPACE_ID must be a workspace GUID, got {workspace_id!r}")
    return ENDPOINT.format(workspace=workspace_id)


def write_dry_run(
    plan: PublishPlan, run_dir: Path, workspace_id: str | None, now: datetime
) -> Path:
    base = run_dir / "publish" / f"{now:%Y%m%dT%H%M%SZ}-sentinel-dry-run"
    folder, number = base, 1
    while True:  # a second dry run in the same second (a double tap) gets its own folder
        try:
            folder.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            number += 1
            folder = base.with_name(f"{base.name}-{number}")
    files = []
    for number, batch in enumerate(plan.batches, start=1):
        path = folder / f"request-{number:03d}.json"
        path.write_text(json.dumps(request_body(batch), indent=2), encoding="utf-8")
        files.append({"file": path.name, "objects": len(batch)})
    url = (
        endpoint(workspace_id)
        if workspace_id
        else ENDPOINT.format(workspace="<SENTINEL_WORKSPACE_ID>")
    )
    manifest = {
        "target": "sentinel",
        "mode": "dry-run: nothing was sent",
        "method": "POST",
        "url": url,
        "headers": {
            "Authorization": "Bearer <acquired only with --apply, never written to disk>",
            "Content-Type": "application/json",
        },
        "requests": files,
        "objects_by_type": dict(plan.counts()),
        "skipped": plan.skipped,
        "approved_hunts_not_uploaded": plan.hunts_not_uploaded,
        "limits": {"objects_per_request": BATCH_SIZE, "requests_per_minute": 100},
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return folder


def retry_after(headers: dict, body: bytes) -> float | None:
    value = {k.lower(): v for k, v in headers.items()}.get("retry-after")
    if value and str(value).strip().isdigit():
        return float(value)
    match = re.search(rb"Try again in (\d+) seconds", body or b"")
    return float(match.group(1)) if match else None


def send(
    plan: PublishPlan,
    workspace_id: str,
    token: Callable[[], str],
    *,
    post: Post | None = None,
    sleep: Callable[[float], None] = time.sleep,
    on_batch: Callable[[BatchResult], None] = lambda r: None,
) -> list[BatchResult]:
    """Upload batch by batch. Stops at the first hard failure; earlier batches stay sent."""
    url = endpoint(workspace_id)
    post = post or urllib_post
    results = []
    for index, batch in enumerate(plan.batches, start=1):
        body = json.dumps(request_body(batch)).encode("utf-8")
        for attempt in range(1, MAX_ATTEMPTS + 1):
            headers = {"Authorization": f"Bearer {token()}", "Content-Type": "application/json"}
            status, response_headers, response_body = post(url, body, headers)
            if status == 200:
                result = BatchResult(index, status, attempt, [o["id"] for o in batch],
                                     _failed(batch, response_body))  # fmt: skip
                results.append(result)
                on_batch(result)
                break
            if status == 429 or status >= 500:
                if attempt == MAX_ATTEMPTS:
                    raise PublishError(f"batch {index}: still HTTP {status} after {attempt} tries")
                wait = retry_after(response_headers, response_body) or 2**attempt
                sleep(min(wait, MAX_WAIT_SECONDS))
                continue
            excerpt = response_body[:300].decode("utf-8", "replace")
            raise PublishError(f"batch {index}: HTTP {status}, stopping: {excerpt}")
    return results


def _failed(batch: list[dict], body: bytes) -> list[dict]:
    if not body or not body.strip():
        return []
    try:
        errors = json.loads(body).get("errors", [])
    except (json.JSONDecodeError, AttributeError):
        return [{"id": None, "type": None, "messages": [body[:300].decode("utf-8", "replace")]}]
    failed = []
    for error in errors:
        index = error.get("recordIndex")
        obj = batch[index] if isinstance(index, int) and 0 <= index < len(batch) else {}
        failed.append(
            {
                "id": obj.get("id"),
                "type": obj.get("type"),
                "messages": error.get("errorMessages", []),
            }
        )
    return failed


def urllib_post(url: str, body: bytes, headers: dict) -> tuple[int, dict, bytes]:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != HOST:
        raise PublishError(f"refusing to send to anything but {HOST}: {url}")
    opener = urllib.request.build_opener(_AllowlistRedirects(frozenset([HOST])))
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(request, timeout=60) as response:
            return response.status, dict(response.headers), response.read()
    except HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read() or b""
    except URLError as exc:
        raise PublishError(f"could not reach {HOST}: {exc}") from exc


def token_provider(settings: Settings, use_az_login: bool) -> Callable[[], str]:
    """The publishing identity, chosen explicitly. Never the DefaultAzureCredential chain,
    which could quietly pick up a broader identity than the one meant for writing. Which
    identity is decided before azure-identity is imported, so a missing choice is reported
    as that, whatever is installed."""
    tenant, client = settings.publish_azure_tenant_id, settings.publish_azure_client_id
    if use_az_login:
        kind = "az login"
    elif tenant and client and settings.publish_azure_client_secret:
        kind = "client secret"
    elif tenant and client and settings.publish_azure_certificate_path:
        kind = "certificate"
    else:
        raise PublishError(
            "choose the publishing identity explicitly: set PUBLISH_AZURE_TENANT_ID, "
            "PUBLISH_AZURE_CLIENT_ID and PUBLISH_AZURE_CLIENT_SECRET (or "
            "PUBLISH_AZURE_CERTIFICATE_PATH), or pass --use-az-login to publish as yourself"
        )
    try:
        from azure.identity import AzureCliCredential, CertificateCredential, ClientSecretCredential
    except ImportError as exc:
        raise PublishError('--apply needs azure-identity: pip install -e ".[azure]"') from exc
    if kind == "az login":
        credential = AzureCliCredential()
    elif kind == "client secret":
        credential = ClientSecretCredential(
            tenant, client, settings.publish_azure_client_secret.get_secret_value()
        )
    else:
        credential = CertificateCredential(
            tenant, client, str(settings.publish_azure_certificate_path)
        )
    return lambda: credential.get_token(TOKEN_SCOPE).token
