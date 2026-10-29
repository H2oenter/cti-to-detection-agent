"""What the bot runs: the same pipeline functions as the CLI, reported to Slack.

Each job owns one status message (Queued → Running → Done or Failed) and posts its results
in a thread, then a reply that mentions the person, because an edited message doesn't
notify a phone.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cti_agent.audit import AuditChainBroken, audit_log_for
from cti_agent.config import Settings
from cti_agent.feeds.fetch import find_advisory, parse_since, run_fetch
from cti_agent.inputs import InputError
from cti_agent.llm.client import FatalLLMError, FixtureMissing, LLMClient
from cti_agent.outputs.sentinel_upload import PublishError
from cti_agent.pipeline import AnalyseError, IngestBlocked, run_analyse, run_ingest, run_prepatch
from cti_agent.slack import blocks
from cti_agent.slack.files import DownloadError, Upload, download
from cti_agent.slack.policy import Exposure, exposure_for, run_tlp, spend_line, spend_refusal
from cti_agent.slack.ports import SlackPort
from cti_agent.slack.render import defang_markdown, mention, mrkdwn, show_hidden
from cti_agent.stages.gate import GateError
from cti_agent.stages.store import has_run_for
from cti_agent.util.locks import LockTimeout

log = logging.getLogger(__name__)
# Errors whose message is written by this tool and safe to show, after rendering.
EXPECTED = (
    AnalyseError, AuditChainBroken, DownloadError, FatalLLMError, FileNotFoundError,
    FixtureMissing, GateError, IngestBlocked, InputError, LockTimeout, PublishError,
)  # fmt: skip


@dataclass
class Deps:
    settings: Settings
    port: SlackPort
    users: dict[str, str]
    client: Callable[[], LLMClient]
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    opener: object | None = None  # the download opener, replaced in tests


@dataclass(frozen=True)
class Ctx:
    user_id: str
    actor: str
    channel: str
    status_ts: str  # the job's status message
    thread_ts: str  # where its results go


class Stopped(Exception):
    """A job ended early for a reason worth telling the person, such as the spend cap."""


def run_job(
    deps: Deps, ctx: Ctx, title: str, kind: str, work: Callable[[], str],
    exposure: Exposure = Exposure.CONTENT,
) -> str:  # fmt: skip
    """Run one job and report it; returns how it ended. A failure's message is shown only
    where the run's content may be: elsewhere, just its kind, with the detail in the log."""
    port = deps.port
    if refusal := spend_refusal(deps.settings, kind, deps.now()):  # checked again at the start
        _tell(port.update, ctx.channel, ctx.status_ts,
              *blocks.job_status(title, "Not started", refusal))  # fmt: skip
        return "Not started"
    _tell(port.update, ctx.channel, ctx.status_ts, *blocks.job_status(title, "Running"))
    try:
        outcome, state = work(), "Done"
    except Stopped as exc:
        outcome, state = str(exc), "Stopped"
    except EXPECTED as exc:
        state = "Failed"
        if exposure is Exposure.CONTENT:
            outcome = mrkdwn(str(exc), 600)
        else:
            log.warning("job failed: %s: %s", title, exc)
            outcome = (f"{type(exc).__name__}; the details aren't shown at this run's TLP, "
                       "so they're in the bot's log")  # fmt: skip
    except Exception:
        log.exception("job failed: %s", title)
        outcome, state = "an unexpected error; the bot's log has the details", "Failed"
    note = f"{outcome} · {spend_line(deps.settings, deps.now())}"
    _tell(port.update, ctx.channel, ctx.status_ts, *blocks.job_status(title, state, note))
    _tell(port.post, ctx.channel,
          [blocks.section(f"{mention(ctx.user_id)} {state.lower()}: {title}")],
          f"{state}: {title}", thread_ts=ctx.thread_ts)  # fmt: skip
    return state


def _tell(send: Callable, *args, **kwargs) -> None:
    """Report to Slack; if Slack fails, log it rather than lose the job's own outcome."""
    try:
        send(*args, **kwargs)
    except Exception:
        log.warning("couldn't report to Slack", exc_info=True)


def _reply(deps: Deps, ctx: Ctx, message: tuple[list[dict], str]) -> None:
    deps.port.post(ctx.channel, *message, thread_ts=ctx.thread_ts)


def known_values(settings: Settings, run_id: str) -> tuple[str, ...]:
    """The run's indicator values, defanged wherever they're shown."""
    path = settings.out_dir / run_id / "validated.json"
    if not path.exists():
        return ()
    items = json.loads(path.read_text(encoding="utf-8"))
    return tuple(a["item"]["value"] for a in items if a.get("item_type") == "indicator")


def _upload_brief(deps: Deps, ctx: Ctx, run_id: str, known: tuple[str, ...]) -> None:
    """The brief as a file: prose defanged as prose (domains and emails too), code as code."""
    path = deps.settings.out_dir / run_id / "brief.md"
    if path.exists():
        text = defang_markdown(show_hidden(path.read_text(encoding="utf-8")), known)
        deps.port.upload_text(ctx.channel, ctx.thread_ts, f"{run_id}-brief.md",
                              "<!-- Defanged for Slack. -->\n" + text, "brief.md")  # fmt: skip


# --- the jobs -----------------------------------------------------------------------------


def fetch_job(deps: Deps, ctx: Ctx, window: str) -> str:
    result = run_fetch(deps.settings, since=parse_since(window))
    _reply(deps, ctx, blocks.fetch_message(result, window))
    passed = sum(t.passed for t in result.triaged)
    return f"{len(result.triaged)} advisories, {passed} to hunt"


def prepatch_job(deps: Deps, ctx: Ctx, advisory_ids: list[str]) -> str:
    settings, done = deps.settings, 0
    for advisory_id in advisory_ids:
        if refusal := spend_refusal(settings, "prepatch", deps.now()):
            raise Stopped(f"{done} of {len(advisory_ids)} done; {refusal}")
        if has_run_for(settings.db_path, advisory_id):
            _reply(deps, ctx, blocks.refused(f"{advisory_id} already has a pre-patch run."))
            continue
        if find_advisory(settings.inbox_dir, advisory_id) is None and advisory_id.startswith(
            "CVE-"
        ):
            run_fetch(settings, since=timedelta(hours=1), sources=(), cve_ids=(advisory_id,))
        result = run_prepatch(advisory_id, settings, deps.client())
        _reply(deps, ctx, blocks.prepatch_message(result))
        _upload_brief(deps, ctx, result.run_id, ())
        done += 1
    return f"{done} pre-patch run(s)"


def ingest_job(deps: Deps, ctx: Ctx, upload: Upload, tlp: str) -> str:
    settings = deps.settings
    token = settings.slack_bot_token.get_secret_value()
    dest = settings.slack_upload_dir / deps.now().strftime("%Y%m%d")
    path = download(upload, token, dest, opener=deps.opener)
    client = deps.client()
    result = run_ingest(path, tlp, settings, client)
    audit_log_for(settings).append(
        run_id=result.run_id, actor=ctx.actor, action="ingest",
        detail={"via": "slack", "slack_file_id": upload.file_id, "file_name": upload.name,
                "tlp": tlp},
    )  # fmt: skip
    exposure = exposure_for(tlp, settings)
    _reply(deps, ctx, blocks.ingest_message(result, tlp, exposure))
    if not result.validation.accepted:
        return f"`{result.run_id}`: nothing accepted, so nothing to analyse"
    if refusal := spend_refusal(settings, "analyse", deps.now()):
        raise Stopped(f"ingested `{result.run_id}`; analysis not started. {refusal}")
    return _analyse(deps, ctx, result.run_id, client, exposure)


def analyse_job(deps: Deps, ctx: Ctx, run_id: str) -> str:
    tlp = run_tlp(deps.settings, run_id)
    if tlp is None:
        raise Stopped(f"there's no run `{run_id}`")
    return _analyse(deps, ctx, run_id, deps.client(), exposure_for(tlp, deps.settings))


def _analyse(deps: Deps, ctx: Ctx, run_id: str, client: LLMClient, exposure: Exposure) -> str:
    analysis = run_analyse(run_id, deps.settings, client)
    known = known_values(deps.settings, run_id)
    _reply(deps, ctx, blocks.analysis_message(analysis, exposure, known))
    if exposure is Exposure.CONTENT:
        _upload_brief(deps, ctx, run_id, known)
    return f"`{run_id}`: {len(analysis.hunts)} hunts to review"


# --- quick answers, posted straight away ---------------------------------------------------


def runs_rows(settings: Settings, limit: int = 10) -> list[dict]:
    if not settings.db_path.exists():
        return []
    rows = []
    with closing(sqlite3.connect(settings.db_path)) as conn:
        try:
            runs = conn.execute(
                "SELECT run_id, created_at, source_file, tlp, status FROM runs "
                "ORDER BY created_at DESC LIMIT ?", (limit,),
            ).fetchall()  # fmt: skip
        except sqlite3.OperationalError:
            return []
        for run_id, created_at, source_file, tlp, status in runs:
            counts: dict[str, int] = {}
            for table in ("objects", "drafts"):
                for state, n in conn.execute(
                    f"SELECT review_status, COUNT(*) FROM {table} WHERE run_id = ? "
                    "GROUP BY review_status", (run_id,),
                ):  # fmt: skip
                    counts[state] = counts.get(state, 0) + n
            content = exposure_for(tlp, settings) is Exposure.CONTENT
            label = _title(settings.out_dir / run_id) or source_file if content else "report"
            rows.append({"run_id": run_id, "created_at": created_at, "tlp": tlp,
                         "status": status, "counts": counts,
                         "label": mrkdwn(label, 200)})  # fmt: skip
    return rows


def _title(run_dir: Path) -> str | None:
    bundle = run_dir / "bundle.json"
    if not bundle.exists():
        return None
    objects = json.loads(bundle.read_text(encoding="utf-8")).get("objects", [])
    return next((o.get("name") for o in objects if o.get("type") == "report"), None)


def audit_reply(settings: Settings, run_id: str) -> tuple[list[dict], str]:
    log_ = audit_log_for(settings)
    try:
        log_.verify()
        verified = "Hash chain verified."
    except AuditChainBroken as exc:
        verified = f"Hash chain BROKEN: {exc}"
    rows = log_.entries(run_id)
    exposure = exposure_for(run_tlp(settings, run_id), settings)
    return blocks.audit_message(run_id, rows, verified, exposure)
