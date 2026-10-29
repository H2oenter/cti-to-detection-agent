"""Publishing from Slack: a dry run first, then a confirm that names the count and the
workspace, then the upload, batch by batch.

Only the app registration can publish from here (`token_provider(..., use_az_login=False)`):
nobody types az login into Slack. The upload sends only the plan whose digest was
confirmed, so approvals that changed after the dry run stop it.
"""

from __future__ import annotations

import logging
import math

from cti_agent import publishing
from cti_agent.audit import audit_log_for
from cti_agent.outputs.sentinel_upload import BATCH_SIZE, PublishError, endpoint, token_provider
from cti_agent.slack import blocks, cards
from cti_agent.slack.jobs import Ctx, Deps, Stopped
from cti_agent.slack.values import MAX_METADATA, encode
from cti_agent.stages.gate import Gate

log = logging.getLogger(__name__)


def upload_ready(settings) -> str | None:
    """Why this machine can't upload, or None. Makes no network call."""
    if not settings.sentinel_workspace_id:
        return "SENTINEL_WORKSPACE_ID isn't set."
    try:
        endpoint(settings.sentinel_workspace_id)
        token_provider(settings, use_az_login=False)
    except PublishError as exc:
        return str(exc)
    return None


def start_dry_run(bot, user: str, run_id: str) -> None:
    bot.enqueue(user, f"publish dry run `{run_id}`", "publish",
                lambda ctx: dry_run_job(bot.deps, ctx, run_id),
                exposure=bot.exposure(run_id))  # fmt: skip


def dry_run_job(deps: Deps, ctx: Ctx, run_id: str) -> str:
    settings = deps.settings
    gate = Gate(settings, run_id, ctx.actor, audit_log_for(settings))
    dry = publishing.dry_run(gate, settings, gate.audit, deps.now())
    deps.port.post(ctx.channel, *cards.dry_run_message(run_id, dry, upload_ready(settings)),
                   thread_ts=ctx.thread_ts)  # fmt: skip
    return f"{len(dry.plan.objects)} objects would be sent; nothing was"


def open_confirm(bot, data: dict, trigger_id: str, message_ts: str) -> None:
    settings = bot.deps.settings
    if reason := upload_ready(settings):
        bot.say(blocks.refused(f"Not publishing: {reason}"), message_ts)
        return
    n = data.get("n", 0)
    metadata = encode(MAX_METADATA, r=data["r"], d=data["d"], n=n, t=message_ts)
    requests = max(1, math.ceil(n / BATCH_SIZE))
    view = cards.publish_modal(metadata, n, requests, settings.sentinel_workspace_id)
    bot.deps.port.open_view(trigger_id, view)


def start_upload(bot, user: str, data: dict) -> None:
    """One upload per confirmed plan at a time. If it fails or stops, the same confirm can be
    sent again once the cause is fixed."""
    title = f"publish `{data['r']}` to Sentinel"
    bot.enqueue(user, title, "publish",
                lambda ctx: upload_job(bot.deps, ctx, data["r"], data["d"], title),
                thread_ts=data.get("t"), key=f"upload:{data['r']}:{data['d']}",
                exposure=bot.exposure(data["r"]))  # fmt: skip


def upload_job(deps: Deps, ctx: Ctx, run_id: str, digest: str, title: str) -> str:
    settings = deps.settings
    if reason := upload_ready(settings):
        raise Stopped(reason)
    gate = Gate(settings, run_id, ctx.actor, audit_log_for(settings))
    token = token_provider(settings, use_az_login=False)

    def progress(result) -> None:
        """Only a report: a Slack hiccup here mustn't stop or fail the upload."""
        note = f"batch {result.index} sent ({len(result.object_ids)} objects)"
        try:
            deps.port.update(ctx.channel, ctx.status_ts,
                             *blocks.job_status(title, "Running", note))  # fmt: skip
        except Exception:
            log.warning("couldn't report batch %s to Slack", result.index, exc_info=True)

    uploaded = publishing.upload(gate, settings, gate.audit, token, expected_digest=digest,
                                 on_batch=progress)  # fmt: skip
    deps.port.post(ctx.channel, *cards.upload_message(run_id, uploaded), thread_ts=ctx.thread_ts)
    sent = len(uploaded.plan.objects) - len(uploaded.failed)
    return f"{sent} uploaded, {len(uploaded.failed)} rejected by Sentinel"
