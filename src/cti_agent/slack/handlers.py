"""What arrives from Slack, and what happens next. app.py acknowledges each payload within
Slack's 3 seconds, then calls in here.

Every payload is checked first: an allowlisted member, in the one channel, on the one
workspace. Anything else is ignored and logged by ID. Pipeline work goes to the job lane;
decisions and quick answers happen at once.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable

from cti_agent.feeds.fetch import top_candidates
from cti_agent.slack import blocks, cards, jobs, publish, review
from cti_agent.slack.files import check_file
from cti_agent.slack.grammar import (
    Analyse,
    Audit,
    Fetch,
    Help,
    Invalid,
    PrepatchOne,
    PrepatchTop,
    Publish,
    Review,
    Runs,
    advisory_id,
    parse_command,
    parse_upload_comment,
)
from cti_agent.slack.jobs import Ctx, Deps
from cti_agent.slack.policy import (
    ESTIMATE_USD,
    Exposure,
    Requester,
    actor,
    exposure_for,
    refusal,
    run_tlp,
    spend_line,
    spend_refusal,
    upload_refusal,
)
from cti_agent.slack.render import escape, mrkdwn
from cti_agent.slack.values import MAX_METADATA, decode, encode
from cti_agent.stages.store import has_run_for

log = logging.getLogger(__name__)
Respond = Callable[[str], None]


class Bot:
    def __init__(self, deps: Deps, lane, team_id: str | None) -> None:
        self.deps, self.lane, self.team_id = deps, lane, team_id
        self._seen: set[str] = set()
        self._seen_lock = threading.Lock()

    # --- checks --------------------------------------------------------------------------

    def allowed(self, kind: str, user_id: str, channel_id: str | None, team_id: str | None) -> bool:
        req = Requester(user_id, channel_id, team_id)
        reason = refusal(req, self.deps.settings, self.deps.users, self.team_id)
        if reason:
            log.info("ignored a %s from %s in %s: %s", kind, user_id, channel_id, reason)
        return reason is None

    def once(self, key: str) -> bool:
        """True the first time a key is seen: Slack can deliver an event twice, and a
        button can be tapped twice."""
        with self._seen_lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def release(self, key: str | None) -> None:
        """Let a key be used again: its job never ran, or ended without finishing."""
        if key is not None:
            with self._seen_lock:
                self._seen.discard(key)

    def exposure(self, run_id: str) -> Exposure:
        settings = self.deps.settings
        return exposure_for(run_tlp(settings, run_id), settings)

    @property
    def channel(self) -> str:
        return self.deps.settings.slack_channel_id

    def say(self, message: tuple[list[dict], str], thread_ts: str | None = None) -> str:
        return self.deps.port.post(self.channel, *message, thread_ts=thread_ts)

    # --- jobs ----------------------------------------------------------------------------

    def enqueue(
        self, user_id: str, title: str, kind: str, work, thread_ts: str | None = None, *,
        key: str | None = None, key_held: bool = False, exposure: Exposure = Exposure.CONTENT,
    ) -> None:  # fmt: skip
        """Post the job's status message and queue it. `title` must already be safe.

        `key` stops the same job running twice (a second tap, a second submit). It's
        released if the job isn't queued or doesn't finish, so it can be tried again."""
        if key is not None and not key_held and not self.once(key):
            self.say(blocks.refused("That's already queued, running or done."), thread_ts)
            return
        settings, now = self.deps.settings, self.deps.now()
        if reason := spend_refusal(settings, kind, now):
            self.release(key)
            self.say(blocks.refused(reason), thread_ts)
            return
        cost = f"about ${ESTIMATE_USD[kind]:.2f}, " if ESTIMATE_USD[kind] else ""
        note = f"{cost}{spend_line(settings, now)}"
        ts = self.say(blocks.job_status(title, "Queued", note), thread_ts)
        ctx = Ctx(user_id, actor(user_id, self.deps.users), self.channel, ts, thread_ts or ts)

        def job() -> None:
            state = jobs.run_job(self.deps, ctx, title, kind, lambda: work(ctx), exposure)
            if state != "Done":
                self.release(key)

        try:
            waiting = self.lane.submit(job)
        except queue.Full:
            self.release(key)
            busy = "Five jobs are already waiting; try again in a few minutes."
            self.deps.port.update(self.channel, ts, *blocks.job_status(title, "Not queued", busy))
            return
        if waiting > 1:
            self.deps.port.update(
                self.channel,
                ts,
                *blocks.job_status(title, "Queued", f"{waiting - 1} ahead · {note}"),
            )

    # --- slash commands ------------------------------------------------------------------

    def on_command(self, body: dict, respond: Respond) -> None:
        user, channel = body.get("user_id", ""), body.get("channel_id")
        if not self.allowed("command", user, channel, body.get("team_id")):
            if user in self.deps.users and channel != self.channel:
                respond("cti-agent only works in its own private channel.")
            return
        command = parse_command(body.get("text", ""))
        log.info("/cti %s from %s", type(command).__name__.lower(), user)  # the kind, not the text
        if isinstance(command, Help):
            respond(escape(blocks.USAGE))
        elif isinstance(command, Invalid):
            respond(escape(command.message))
        elif isinstance(command, Runs):
            self.say(blocks.runs_message(jobs.runs_rows(self.deps.settings)))
        elif isinstance(command, Audit):
            self.on_run(user, command.run_id, "audit", respond)
        elif isinstance(command, Fetch):
            title = f"fetch, last {escape(command.window)}"
            self.enqueue(user, title, "fetch",
                         lambda ctx: jobs.fetch_job(self.deps, ctx, command.window))  # fmt: skip
        elif isinstance(command, PrepatchTop):
            self.offer_prepatch(command.n)
        elif isinstance(command, PrepatchOne):
            self.start_prepatch(user, [command.advisory_id])
        elif isinstance(command, Analyse | Review | Publish):
            verb = {Analyse: "analyse", Review: "review", Publish: "publish"}[type(command)]
            self.on_run(user, command.run_id, verb, respond)

    def on_run(self, user: str, run_id: str, verb: str, respond: Respond | None = None) -> None:
        if run_tlp(self.deps.settings, run_id) is None:
            message = f"There's no run {run_id}. `/cti runs` lists them."
            if respond:
                respond(escape(message))
            else:
                self.say(blocks.refused(message))
            return
        if verb == "audit":
            self.say(jobs.audit_reply(self.deps.settings, run_id))
        elif verb == "analyse":
            self.enqueue(user, f"analyse `{run_id}`", "analyse",
                         lambda ctx: jobs.analyse_job(self.deps, ctx, run_id),
                         exposure=self.exposure(run_id))  # fmt: skip
        elif verb == "review":
            review.post_review(self, user, run_id)
        elif verb == "publish":
            publish.start_dry_run(self, user, run_id)

    def offer_prepatch(self, n: int) -> None:
        settings = self.deps.settings
        ids = [
            i for i in top_candidates(settings.inbox_dir, n) if not has_run_for(settings.db_path, i)
        ]
        if not ids:
            self.say(blocks.refused("Nothing new to hunt: run /cti fetch first, or every top "
                                    "advisory already has a pre-patch run."))  # fmt: skip
            return
        spend = spend_line(settings, self.deps.now())
        self.say(blocks.prepatch_list(ids, ESTIMATE_USD["prepatch"], spend))

    def start_prepatch(self, user: str, ids: list[str], key: str | None = None) -> None:
        listed = ", ".join(mrkdwn(i, 80) for i in ids)
        self.enqueue(user, f"pre-patch {listed}", "prepatch",
                     lambda ctx: jobs.prepatch_job(self.deps, ctx, ids), key=key)  # fmt: skip

    # --- an uploaded report ----------------------------------------------------------------

    # Slack now delivers an upload as an ordinary message that carries `files`; older
    # workspaces may still mark it with the file_share subtype. Edits, deletions, joins and
    # bot posts have other subtypes and are never uploads.
    UPLOAD_SUBTYPES = (None, "file_share")

    def on_message(self, event: dict, team_id: str | None) -> None:
        """Every message in the channel arrives here; only an upload with `ingest tlp:…`
        does anything."""
        if event.get("subtype") not in self.UPLOAD_SUBTYPES or not event.get("files"):
            return
        user, thread = event.get("user", ""), event.get("ts")
        if not self.allowed("upload", user, event.get("channel"), team_id):
            return
        request = parse_upload_comment(event.get("text", ""))
        if request is None:
            log.info("a file from %s with no `ingest tlp:…` comment: left alone", user)
            return  # a file shared for people, not for the bot
        log.info("upload from %s, %s", user, getattr(request, "tlp", "comment not understood"))
        if isinstance(request, Invalid):
            self.say(blocks.refused(request.message), thread)
            return
        files = event.get("files") or []
        if len(files) != 1:
            self.say(blocks.refused("Upload one report at a time."), thread)
            return
        file_id = str(files[0].get("id", ""))
        key = f"file:{file_id}"
        if not self.once(key):
            return  # Slack delivered the same upload again
        if reason := upload_refusal(request.tlp, self.deps.settings):
            advice = "Please delete the file from this channel: Slack keeps whatever it's given."
            self.say(blocks.refused(f"Not ingested: {reason} {advice}"), thread)
            return
        try:
            info = self.deps.port.file_info(file_id)
        except Exception:
            log.warning("files.info failed for %s", file_id, exc_info=True)
            self.release(key)
            self.say(blocks.refused("Slack didn't return the file's details, so nothing was "
                                    "ingested. Upload it again in a moment."), thread)  # fmt: skip
            return
        upload = check_file(info)
        if isinstance(upload, str):
            self.say(blocks.refused(f"Not ingested: {upload}."), thread)
            return
        title = f"ingest {mrkdwn(upload.name, 120)} (TLP:{request.tlp})"
        self.enqueue(user, title, "ingest",
                     lambda ctx: jobs.ingest_job(self.deps, ctx, upload, request.tlp),
                     thread_ts=thread, key=key, key_held=True,
                     exposure=exposure_for(request.tlp, self.deps.settings))  # fmt: skip

    # --- buttons and menus -----------------------------------------------------------------

    def on_action(self, body: dict) -> None:
        user = (body.get("user") or {}).get("id", "")
        channel = (body.get("channel") or {}).get("id")
        team = (body.get("team") or {}).get("id") or (body.get("user") or {}).get("team_id")
        if not self.allowed("click", user, channel, team):
            return
        message_ts = (body.get("container") or {}).get("message_ts", "")
        thread_ts = (body.get("message") or {}).get("thread_ts") or message_ts
        for action in body.get("actions") or []:
            action_id = action.get("action_id", "")
            value = action.get("value") or (action.get("selected_option") or {}).get("value")
            log.info("tap on %s from %s", action_id[:40], user)
            self.on_click(user, action_id, value, message_ts, body.get("trigger_id", ""),
                          thread_ts)  # fmt: skip

    def on_click(self, user: str, action_id: str, value: str | None, message_ts: str,
                 trigger_id: str, thread_ts: str | None = None) -> None:  # fmt: skip
        thread_ts = thread_ts or message_ts
        if action_id == "cti_prepatch_top" and (data := decode(value, "n")):
            if 1 <= data["n"] <= 10:
                self.offer_prepatch(data["n"])
        elif action_id == "cti_prepatch_go" and (data := decode(value, "ids")):
            if ids := [found for i in data["ids"][:10] if (found := advisory_id(i))]:
                self.start_prepatch(user, ids, key=f"click:{message_ts}:{action_id}")
        elif action_id in ("cti_review", "cti_publish") and (data := decode(value, "r")):
            self.on_run(user, data["r"], action_id.removeprefix("cti_"))
        elif action_id == "cti_run_menu" and (data := decode(value, "r", "a")):
            if data["a"] in ("review", "publish", "audit"):
                self.on_run(user, data["r"], data["a"])
        elif action_id == "cti_approve" and (data := decode(value, "r", "i", "h")):
            review.decide_card(self, user, data, "approve", None, message_ts)
        elif action_id in ("cti_approve_clean", "cti_approve_kind") and (
            data := decode(value, "r", "k", "d")
        ):
            review.decide_list(self, user, data, "approve", None, message_ts)
        elif action_id == "cti_reject" and (data := decode(value, "r", "i", "h")):
            metadata = encode(MAX_METADATA, a="item", t=message_ts,
                              **{k: data[k] for k in ("r", "i", "h")})  # fmt: skip
            self.deps.port.open_view(trigger_id, cards.reject_modal(metadata, "this item"))
        elif action_id == "cti_reject_kind" and (data := decode(value, "r", "k", "d", "n")):
            metadata = encode(MAX_METADATA, a="list", t=message_ts,
                              **{k: data[k] for k in ("r", "k", "d", "n")})  # fmt: skip
            what = f"all {data['n']} {cards.plural(data['k'], data['n'])}"
            self.deps.port.open_view(trigger_id, cards.reject_modal(metadata, what))
        elif action_id == "cti_one_by_one" and (data := decode(value, "r", "k")):
            review.next_page(self, user, data, thread_ts)
        elif action_id == "cti_publish_confirm" and (data := decode(value, "r", "d", "n")):
            publish.open_confirm(self, data, trigger_id, thread_ts)

    # --- modals ---------------------------------------------------------------------------------

    @staticmethod
    def view_errors(body: dict) -> dict | None:
        """Checked before the modal is acknowledged, so Slack can show the error in place."""
        view = body.get("view") or {}
        if view.get("callback_id") != "cti_reject_reason":
            return None
        if not _reason(view).strip():
            return {"reason": "Give a reason: it goes in the audit log."}
        return None

    def on_view(self, body: dict) -> None:
        view, user = body.get("view") or {}, (body.get("user") or {}).get("id", "")
        team = (body.get("team") or {}).get("id") or (body.get("user") or {}).get("team_id")
        if not self.allowed("modal", user, self.channel, team):
            return
        callback = view.get("callback_id")
        log.info("submit of %s from %s", str(callback)[:40], user)
        if callback == "cti_reject_reason" and (data := decode(view.get("private_metadata"),
                                                                "r", "a", "t")):  # fmt: skip
            reason = _reason(view).strip()[:500]
            if not reason:
                return
            if data["a"] == "item" and {"i", "h"} <= data.keys():
                review.decide_card(self, user, data, "reject", reason, data["t"])
            elif data["a"] == "list" and {"k", "d"} <= data.keys():
                review.decide_list(self, user, data, "reject", reason, data["t"])
        elif callback == "cti_publish_upload" and (
            data := decode(view.get("private_metadata"), "r", "d")
        ):
            publish.start_upload(self, user, data)


def _reason(view: dict) -> str:
    values = (view.get("state") or {}).get("values") or {}
    return str(((values.get("reason") or {}).get("reason") or {}).get("value") or "")
