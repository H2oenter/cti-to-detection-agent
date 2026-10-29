"""The Slack wiring: Bolt in Socket Mode. The only module that imports the Slack libraries.

The bot opens an outbound connection to Slack, so there's no open port and no public URL.
At startup, and again before posting (every few minutes at most), it checks that its
channel is private, not shared, and has the bot in it. Every payload is acknowledged
within Slack's 3 seconds before anything else happens.
"""

from __future__ import annotations

import logging
import re
import threading
import time

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.errors import SlackApiError
from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler

from cti_agent.config import Settings
from cti_agent.llm.client import live_client
from cti_agent.slack.blocks import section, validate
from cti_agent.slack.handlers import Bot
from cti_agent.slack.jobs import Deps
from cti_agent.slack.policy import ChannelGuard, channel_problem, config_problems, parse_users
from cti_agent.slack.worker import Lane

log = logging.getLogger("cti_agent.slack")


class SetupError(Exception):
    pass


class ChannelUnsafe(Exception):
    """The channel stopped being private, unshared and joined, so nothing is posted."""


class WebClientPort:
    """SlackPort over Slack's web client: previews off on every post, about one message a
    second, Slack's rate-limit answers retried, and the channel checked again (at most every
    few minutes) before anything is posted to it."""

    def __init__(self, client, guard: ChannelGuard | None = None) -> None:
        self.client = client
        self.guard = guard
        client.retry_handlers.append(RateLimitErrorRetryHandler(max_retry_count=2))
        self._lock = threading.Lock()
        self._last = 0.0

    def _check(self) -> None:
        if self.guard and (problem := self.guard.problem()):
            log.error("not posting: %s", problem)
            raise ChannelUnsafe(problem)

    def _pace(self) -> None:
        with self._lock:
            wait = self._last + 1.0 - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    @staticmethod
    def _fit(blocks: list[dict], text: str) -> list[dict]:
        if problems := validate(blocks):
            log.warning("a message was over Slack's limits, so only its summary was sent: %s",
                        problems)  # fmt: skip
            return [section(text)]
        return blocks

    def post(self, channel, blocks, text, thread_ts=None) -> str:
        self._check()
        self._pace()
        response = self.client.chat_postMessage(
            channel=channel, blocks=self._fit(blocks, text), text=text, thread_ts=thread_ts,
            unfurl_links=False, unfurl_media=False,
        )  # fmt: skip
        return response["ts"]

    def update(self, channel, ts, blocks, text) -> None:
        self._check()
        self.client.chat_update(channel=channel, ts=ts, blocks=self._fit(blocks, text), text=text)

    def upload_text(self, channel, thread_ts, filename, content, title) -> None:
        self._check()
        self._pace()
        self.client.files_upload_v2(channel=channel, thread_ts=thread_ts, filename=filename,
                                    content=content, title=title)  # fmt: skip

    def open_view(self, trigger_id, view) -> None:
        self.client.views_open(trigger_id=trigger_id, view=view)

    def file_info(self, file_id) -> dict:
        return self.client.files_info(file=file_id)["file"]


def register(app: App, bot: Bot) -> None:
    @app.command("/cti")
    def on_command(ack, body, respond):
        ack()
        bot.on_command(body, lambda text: respond(text=text, response_type="ephemeral"))

    # Registered before the catch-all below: Bolt runs the first listener that matches.
    @app.event({"type": "message", "subtype": "file_share"})
    def on_file_share(event, body):
        bot.on_file_share(event, body.get("team_id"))

    @app.event("message")
    def on_any_other_message():
        """Every message in the channel arrives (groups:history); only uploads matter."""

    @app.action(re.compile(r"^cti_"))
    def on_action(ack, body):
        ack()
        bot.on_action(body)

    @app.view(re.compile(r"^cti_"))
    def on_view(ack, body):
        if errors := bot.view_errors(body):
            ack(response_action="errors", errors=errors)
            return
        ack()
        bot.on_view(body)


def run(settings: Settings, check_only: bool = False) -> str:
    """Connect and serve until Ctrl+C. With check_only, check the settings and the channel
    and return without serving."""
    if problems := config_problems(settings):
        raise SetupError("; ".join(problems))
    users, _ = parse_users(settings.slack_users)
    try:
        app = App(token=settings.slack_bot_token.get_secret_value())
        auth = app.client.auth_test()
        info = app.client.conversations_info(channel=settings.slack_channel_id)["channel"]
    except SlackApiError as exc:
        raise SetupError(f"Slack refused: {exc.response.get('error', 'unknown error')}") from None
    if problem := channel_problem(info):
        raise SetupError(problem)
    where = f"#{info.get('name', settings.slack_channel_id)} in {auth.get('team', 'Slack')}"
    if check_only:
        return where
    lane = Lane()
    lane.start()
    guard = ChannelGuard(
        lambda: app.client.conversations_info(channel=settings.slack_channel_id)["channel"]
    )
    port = WebClientPort(app.client, guard)
    deps = Deps(settings, port, users, client=lambda: live_client(settings))
    register(app, Bot(deps, lane, auth["team_id"]))
    handler = SocketModeHandler(app, settings.slack_app_token.get_secret_value())
    handler.connect()
    log.info("connected; listening in %s for %d member(s)", where, len(users))
    try:
        while True:  # a timed wait, so Ctrl+C stops it on Windows too
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("stopping; queued jobs are dropped")
    finally:
        handler.close()
        lane.stop()
    return where
