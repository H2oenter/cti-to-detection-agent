"""Publishing approved STIX objects to Sentinel, shared by the CLI and the Slack bot so
both leave the same audit entries.

A dry run writes the exact requests and sends nothing. An upload needs the digest of the
plan the person confirmed: if approvals changed in between, nothing is sent. Only one
upload of a run can be in progress, from any process.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.audit import AuditLog
from cti_agent.config import Settings
from cti_agent.outputs.sentinel_upload import (
    BatchResult,
    PublishError,
    PublishPlan,
    plan_sentinel,
    send,
    write_dry_run,
)
from cti_agent.stages.gate import Gate
from cti_agent.stages.store import mark_published
from cti_agent.util.locks import InterProcessLock
from cti_agent.util.normalise import canonical_json, sha256_bytes

logger = logging.getLogger(__name__)


def plan_digest(plan: PublishPlan) -> str:
    """A fingerprint of exactly what would be sent."""
    objects = sorted(plan.objects, key=lambda o: o["id"])
    return sha256_bytes(canonical_json(objects).encode("utf-8"))[:32]


@dataclass
class DryRun:
    plan: PublishPlan
    folder: Path
    digest: str


@dataclass
class Uploaded:
    plan: PublishPlan
    results: list[BatchResult]

    @property
    def failed(self) -> list[dict]:
        return [f for r in self.results for f in r.failed]


def dry_run(gate: Gate, settings: Settings, log: AuditLog, now: datetime | None = None) -> DryRun:
    plan = plan_sentinel(gate)
    folder = write_dry_run(
        plan, gate.out_dir, settings.sentinel_workspace_id, now or datetime.now(UTC)
    )
    digest = plan_digest(plan)
    log.append(
        run_id=gate.run_id, actor=gate.actor, action="publish", decision="dry-run",
        detail={"target": "sentinel", "objects": len(plan.objects),
                "requests": len(plan.batches), "folder": folder.name, "digest": digest},
    )  # fmt: skip
    return DryRun(plan, folder, digest)


def upload(
    gate: Gate,
    settings: Settings,
    log: AuditLog,
    token: Callable[[], str],
    *,
    expected_digest: str,
    on_batch: Callable[[BatchResult], None] = lambda r: None,
    sleep: Callable[[float], None] | None = None,
) -> Uploaded:
    """Send the plan the person confirmed, batch by batch, recording each batch in the audit
    log and marking what was published. Raises PublishError if it stops."""
    with InterProcessLock(gate.out_dir / "publish" / ".lock", timeout=5):
        plan = plan_sentinel(gate)
        if plan_digest(plan) != expected_digest:
            raise PublishError(
                "what would be sent changed since you confirmed it; nothing was sent, so "
                "run the dry run again"
            )

        def record(result: BatchResult) -> None:
            log.append(
                run_id=gate.run_id, actor=gate.actor, action="publish_batch",
                decision="sent" if not result.failed else "partly rejected",
                detail={"target": "sentinel", "batch": result.index, "status": result.status,
                        "attempts": result.attempts, "objects": result.object_ids,
                        "failed": result.failed},
            )  # fmt: skip
            mark_published(settings.db_path, gate.run_id, result)
            try:  # a progress report; it must never stop the upload or skip its records
                on_batch(result)
            except Exception:
                logger.warning("reporting batch %s failed", result.index, exc_info=True)

        try:
            results = send(
                plan, settings.sentinel_workspace_id, token, on_batch=record,
                **({"sleep": sleep} if sleep else {}),
            )  # fmt: skip
        except PublishError as exc:
            log.append(run_id=gate.run_id, actor=gate.actor, action="publish", decision="failed",
                       reason=str(exc), detail={"target": "sentinel"})  # fmt: skip
            raise
        uploaded = Uploaded(plan, results)
        log.append(
            run_id=gate.run_id, actor=gate.actor, action="publish", decision="applied",
            detail={"target": "sentinel", "objects": len(plan.objects),
                    "failed": len(uploaded.failed)},
        )  # fmt: skip
        return uploaded
