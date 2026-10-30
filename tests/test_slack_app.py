"""The Bolt wiring, with the Slack libraries but no network: requests are dispatched to the
app directly, and the web client is a stand-in. Skipped unless the [slack] extra is
installed, as in CI."""

import json
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("slack_bolt")

from slack_bolt import App, BoltRequest
from slack_sdk import WebClient
from slack_sdk.web.slack_response import SlackResponse

from cti_agent.slack.app import (
    SetupError,
    WebClientPort,
    channel_problem,
    register,
    single_instance,
)
from cti_agent.slack.blocks import section

TEAM = "T0TEAM001"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("these tests must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def offline_auth_test(self, **kwargs):
    """auth.test, which Bolt calls before the first request, answered locally. Bolt makes a
    fresh client for each request, so this replaces the method on the class."""
    data = {"ok": True, "team_id": TEAM, "user_id": "U0BOT0001", "bot_id": "B0BOT0001",
            "team": "Test"}  # fmt: skip
    url = "https://slack.com/api/auth.test"
    return SlackResponse(client=self, http_verb="POST", api_url=url, req_args={}, data=data,
                         headers={}, status_code=200)  # fmt: skip


class RecordingBot:
    def __init__(self):
        self.calls = []

    def on_command(self, body, respond):
        self.calls.append(("command", body["text"]))

    def on_message(self, event, team_id):
        self.calls.append(("message", event.get("subtype"), bool(event.get("files")), team_id))

    def on_action(self, body):
        self.calls.append(("action", body["actions"][0]["action_id"]))

    def view_errors(self, body):
        value = body["view"]["state"]["values"]["reason"]["reason"]["value"]
        return None if value.strip() else {"reason": "Give a reason"}

    def on_view(self, body):
        self.calls.append(("view", body["view"]["callback_id"]))


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setattr(WebClient, "auth_test", offline_auth_test)
    app = App(token="xoxb-test-not-real", token_verification_enabled=False,
              process_before_response=True)  # fmt: skip
    bot = RecordingBot()
    register(app, bot)
    return app, bot


def dispatch(app, body):
    return app.dispatch(BoltRequest(body=body, mode="socket_mode"))


def test_commands_uploads_clicks_and_modals_reach_the_bot(wired):
    app, bot = wired
    base = {"team_id": TEAM, "user_id": "U0SAMUEL1", "channel_id": "C0CHANNEL1"}
    assert dispatch(app, {**base, "command": "/cti", "text": "runs",
                          "response_url": "https://hooks.slack.com/x", "trigger_id": "t"}).status == 200  # noqa: E501  # fmt: skip
    message = {"type": "message", "user": "U0SAMUEL1", "channel": "C0CHANNEL1", "ts": "1.2",
               "text": "ingest tlp:clear", "files": [{"id": "F0123ABCD"}]}  # fmt: skip
    for event in (message,  # an upload as Slack sends it now: no subtype
                  {**message, "subtype": "file_share"},  # as it used to
                  {**message, "files": [], "text": "hi"}):  # fmt: skip
        dispatch(app, {"type": "event_callback", "team_id": TEAM, "event": event})
    user = {"id": "U0SAMUEL1", "team_id": TEAM}
    dispatch(app, {"type": "block_actions", "user": user, "team": {"id": TEAM},
                   "channel": {"id": "C0CHANNEL1"}, "trigger_id": "t",
                   "container": {"message_ts": "1.4"},
                   "actions": [{"action_id": "cti_approve", "value": "{}"}]})  # fmt: skip
    view = {"type": "modal", "callback_id": "cti_reject_reason", "private_metadata": "{}",
            "state": {"values": {"reason": {"reason": {"value": ""}}}}}  # fmt: skip
    refused = dispatch(app, {"type": "view_submission", "user": user, "team": {"id": TEAM},
                             "view": view})  # fmt: skip
    assert json.loads(refused.body)["response_action"] == "errors"
    view["state"]["values"]["reason"]["reason"]["value"] = "sinkholed"
    dispatch(app, {"type": "view_submission", "user": user, "team": {"id": TEAM}, "view": view})
    assert bot.calls == [
        ("command", "runs"),
        ("message", None, True, TEAM),  # every message reaches the bot, which decides
        ("message", "file_share", True, TEAM),
        ("message", None, False, TEAM),
        ("action", "cti_approve"),
        ("view", "cti_reject_reason"),
    ]


class RecordingClient:
    def __init__(self):
        self.retry_handlers, self.calls = [], []

    def chat_postMessage(self, **kwargs):
        self.calls.append(kwargs)
        return {"ts": "1.5"}


def test_every_post_has_previews_off_and_oversized_ones_send_the_summary(monkeypatch):
    monkeypatch.setattr("cti_agent.slack.app.time.sleep", lambda s: None)
    client = RecordingClient()
    port = WebClientPort(client)
    port.post("C0CHANNEL1", [section("ok")], "summary")
    port.post("C0CHANNEL1", [section("x")] * 51, "the summary")
    first, second = client.calls
    assert all(c["unfurl_links"] is False and c["unfurl_media"] is False for c in client.calls)
    assert first["blocks"] == [section("ok")]
    assert second["blocks"] == [section("the summary")]
    assert client.retry_handlers  # Slack's rate-limit answers are retried


@pytest.mark.parametrize(
    ("channel", "problem"),
    [
        ({"is_private": True, "is_member": True}, None),
        ({"is_private": False, "is_member": True}, "private"),
        ({"is_private": True, "is_ext_shared": True, "is_member": True}, "shared"),
        ({"is_private": True, "is_member": False}, "invite the bot"),
    ],
)
def test_the_channel_must_be_private_unshared_and_joined(channel, problem):
    found = channel_problem(channel)
    assert found is None if problem is None else problem in found


BOT = """
import sys, time
from pathlib import Path
from types import SimpleNamespace
from cti_agent.slack.app import single_instance
single_instance(SimpleNamespace(out_dir=Path(sys.argv[1])))
print("running", flush=True)
time.sleep(30)
"""


def test_a_second_bot_on_the_same_machine_refuses_to_start(tmp_path):
    """Found on the live run: a second copy, started in another terminal, quietly took
    some of the taps, so each copy's log showed only part of what happened."""
    first = subprocess.Popen([sys.executable, "-c", BOT, str(tmp_path)],
                             stdout=subprocess.PIPE, text=True)  # fmt: skip
    try:
        assert first.stdout.readline().strip() == "running"
        with pytest.raises(SetupError, match="already running"):
            single_instance(SimpleNamespace(out_dir=tmp_path))
    finally:
        first.kill()
        first.wait(timeout=30)
    for _ in range(100):  # the OS frees the lock when the process ends, at times a beat later
        try:
            single_instance(SimpleNamespace(out_dir=tmp_path)).release()
            break
        except SetupError:
            time.sleep(0.1)
    else:
        pytest.fail("the lock wasn't freed after the first bot ended")
