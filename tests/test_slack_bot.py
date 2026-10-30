"""The Slack bot end to end against a fake Slack: uploads, commands, review and publish.
Pipeline runs replay recorded model answers or use the fake models; nothing touches the
network."""

import io
import json
import socket
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import AA23_ATTACK, AA23_REPORT, FIXTURE_REPORT, FIXTURES, FakeAnalyst, FakeModel
from pydantic import SecretStr

from cti_agent.audit import audit_log_for
from cti_agent.llm.client import FixtureMissing, ReplayClient
from cti_agent.slack import blocks, cards, jobs, review
from cti_agent.slack.handlers import Bot
from cti_agent.slack.jobs import Deps
from cti_agent.slack.worker import InlineLane

USER, CHANNEL, TEAM = "U0SAMUEL1", "C0CHANNEL1", "T0TEAM001"
UPLOAD_TS = "1700000000.000100"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("these tests must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class FakeSlack:
    """Records everything the bot sends, as Slack would receive it."""

    def __init__(self, files=None):
        self.posts, self.updates, self.uploads, self.views = [], [], [], []
        self.files = files or {}
        self.order = []  # ("post", ts) and ("upload", filename), as they happened

    def post(self, channel, blocks, text, thread_ts=None):
        ts = f"1700000001.{len(self.posts):06d}"
        self.posts.append({"channel": channel, "blocks": blocks, "text": text,
                           "thread_ts": thread_ts, "ts": ts})  # fmt: skip
        self.order.append(("post", ts))
        return ts

    def update(self, channel, ts, blocks, text):
        self.updates.append({"channel": channel, "ts": ts, "blocks": blocks, "text": text})

    def upload_text(self, channel, thread_ts, filename, content, title):
        self.uploads.append({"channel": channel, "thread_ts": thread_ts, "filename": filename,
                             "content": content, "title": title})  # fmt: skip
        self.order.append(("upload", filename))

    def open_view(self, trigger_id, view):
        self.views.append({"trigger_id": trigger_id, "view": view})

    def file_info(self, file_id):
        return self.files[file_id]

    def sent(self) -> str:
        return json.dumps([self.posts, self.updates, self.uploads, self.views])

    def texts(self) -> list[str]:
        return [json.dumps(p["blocks"]) for p in self.posts]


class FakeOpener:
    def __init__(self, data):
        self.data, self.requests = data, []

    def open(self, request, timeout=None):
        self.requests.append(request)
        return io.BytesIO(self.data)


class Folders:
    """Replays from several recording folders and never records anything."""

    def __init__(self, *folders):
        self.clients = [ReplayClient(f) for f in folders]

    def structured(self, **kwargs):
        for client in self.clients:
            try:
                return client.structured(**kwargs)
            except FixtureMissing:
                continue
        raise FixtureMissing("no recording in any folder")


class Fakes:
    """The fake collector and re-check for extraction, the fake analyst for the rest."""

    def __init__(self):
        self.model, self.analyst = FakeModel(), FakeAnalyst()

    def structured(self, *, schema, **kwargs):
        fake = self.model if schema.__name__ in ("Extraction", "RoleCheck") else self.analyst
        return fake.structured(schema=schema, **kwargs)


@pytest.fixture
def slack_settings(settings, tmp_path):
    return settings.model_copy(update={
        "slack_bot_token": SecretStr("xoxb-test-not-real"),
        "slack_app_token": SecretStr("xapp-test-not-real"),
        "slack_channel_id": CHANNEL,
        "slack_users": f"{USER}=Samuel",
        "slack_upload_dir": tmp_path / "uploads",
        "inbox_dir": tmp_path / "inbox",
    })  # fmt: skip


def make_bot(settings, client, files=None, data=b""):
    port = FakeSlack(files)
    opener = FakeOpener(data)
    deps = Deps(settings, port, {USER: "Samuel"}, client=lambda: client, opener=opener)
    return Bot(deps, InlineLane(), TEAM), port, opener


def file_info(name, data, file_id="F0123ABCD"):
    return {file_id: {
        "id": file_id, "name": name, "mode": "hosted", "size": len(data),
        "url_private_download": f"https://files.slack.com/files-pri/{TEAM}-{file_id}/download/x",
    }}  # fmt: skip


def upload_event(comment="ingest tlp:clear", user=USER, channel=CHANNEL, file_id="F0123ABCD",
                 subtype=None):  # fmt: skip
    """An upload as Slack sends it today: an ordinary message carrying `files`, with no
    subtype. Older deliveries mark it file_share."""
    event = {"type": "message", "user": user, "channel": channel, "ts": UPLOAD_TS,
             "text": comment, "files": [{"id": file_id}], "upload": True}  # fmt: skip
    return {**event, "subtype": subtype} if subtype else event


def aa23_bot(slack_settings):
    settings = slack_settings.model_copy(
        update={"attack_bundle": AA23_ATTACK[0], "attack_mobile_bundle": AA23_ATTACK[1]}
    )
    data = AA23_REPORT.read_bytes()
    client = Folders(FIXTURES / "llm" / "aa23-320a", FIXTURES / "llm" / "aa23-320a-analyse")
    return make_bot(settings, client, file_info("aa23-320a.txt", data), data)


def run_ids(settings):
    if not settings.out_dir.exists():
        return []
    return sorted(p.name for p in settings.out_dir.iterdir() if p.is_dir() and p.name[0] == "2")


# --- an uploaded report -----------------------------------------------------------------------


def test_an_upload_is_ingested_then_analysed_and_reported(slack_settings):
    bot, slack, opener = aa23_bot(slack_settings)
    bot.on_message(upload_event(), TEAM)

    status = slack.posts[0]
    assert status["thread_ts"] == UPLOAD_TS and status["text"].startswith(
        "Queued: ingest aa23-320a[.]txt"
    )
    states = [u["text"].split(":")[0] for u in slack.updates]
    assert states == ["Running", "Done"]
    posted = " ".join(slack.texts())
    assert "*Ingested*" in posted and "*Analysed*" in posted and "41 techniques" in posted
    assert slack.uploads[0]["filename"].endswith("-brief.md")
    assert slack.uploads[0]["content"].startswith("<!-- Defanged for Slack. -->")
    assert slack.posts[-1]["blocks"][0]["text"]["text"].startswith(f"<@{USER}> done: ingest")
    assert all(p["thread_ts"] == UPLOAD_TS for p in slack.posts)
    assert all(blocks.validate(p["blocks"]) == [] for p in slack.posts)

    (run_id,) = run_ids(bot.deps.settings)
    saved = list((bot.deps.settings.slack_upload_dir).rglob("*.txt"))
    assert [p.name for p in saved] == ["F0123ABCD.txt"]  # the uploaded name isn't a path
    entry = next(e for e in audit_log_for(bot.deps.settings).entries(run_id)
                 if e["action"] == "ingest")  # fmt: skip
    assert entry["actor"] == f"slack:{USER} (Samuel)"
    assert entry["detail"] == {"via": "slack", "slack_file_id": "F0123ABCD",
                               "file_name": "aa23-320a.txt", "tlp": "CLEAR"}  # fmt: skip
    assert opener.requests[0].unredirected_hdrs["Authorization"] == "Bearer xoxb-test-not-real"


def test_live_indicators_never_reach_slack(slack_settings):
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(), TEAM)
    sent = slack.sent()
    assert "*Analysed*" in sent  # it ran all the way through
    for live in ("198.51.101.7", "helpdesk-reset-fixture.net", "https://"):
        assert live not in sent
    assert "xoxb-test-not-real" not in sent


def test_amber_strict_shows_counts_and_nothing_else(slack_settings):
    settings = slack_settings.model_copy(
        update={"slack_approved_for_amber": True, "endpoint_approved_for_amber": True}
    )
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(settings, Fakes(), file_info("fx-2026-01.txt", data), data)
    bot.on_message(upload_event("ingest tlp:amber+strict"), TEAM)
    sent = slack.sent()
    assert "Content isn't shown at TLP:AMBER+STRICT" in sent and "*Analysed*" in sent
    assert "Joint Advisory FX-2026-01" not in sent and slack.uploads == []
    assert "For leadership" not in sent and "Needs a look" not in sent


@pytest.mark.parametrize(
    ("comment", "message"),
    [
        ("ingest tlp:red", "TLP:RED never goes"),
        ("ingest tlp:amber", "isn't approved for TLP:AMBER"),
    ],
)
def test_refused_uploads_are_never_downloaded(slack_settings, comment, message):
    bot, slack, opener = make_bot(slack_settings, Fakes())  # no files: file_info would fail
    bot.on_message(upload_event(comment), TEAM)
    (reply,) = slack.posts
    assert message in reply["text"] and "delete the file" in reply["text"]
    assert opener.requests == [] and run_ids(bot.deps.settings) == []


@pytest.mark.parametrize(
    "event",
    [
        upload_event(user="U0STRANGER"),
        upload_event(channel="C0GENERAL1"),
        upload_event(comment="Here's the lunch menu"),
        upload_event(subtype="message_changed"),
        upload_event(subtype="bot_message"),
        {**upload_event(), "files": []},  # "ingest tlp:clear" typed with no file attached
    ],
)
def test_other_people_places_and_files_are_ignored(slack_settings, event):
    bot, slack, opener = make_bot(slack_settings, Fakes())
    bot.on_message(event, TEAM)
    bot.on_message(upload_event(), "T0OTHER01")  # another workspace
    assert slack.posts == [] and opener.requests == []


@pytest.mark.parametrize("subtype", [None, "file_share"])
def test_an_upload_is_picked_up_whether_or_not_slack_marks_it_file_share(slack_settings, subtype):
    """Found on the first live run: Slack sent the upload as a plain message with `files`,
    and a listener for the file_share subtype never saw it."""
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, opener = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(subtype=subtype), TEAM)
    assert opener.requests and slack.posts[0]["text"].startswith("Queued: ingest")
    assert len(run_ids(bot.deps.settings)) == 1


def test_a_bad_comment_gets_the_usage_and_one_upload_runs_once(slack_settings):
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event("ingest please"), TEAM)
    assert "no default" in slack.posts[0]["text"]
    bot.on_message(upload_event(), TEAM)
    bot.on_message(upload_event(), TEAM)  # Slack delivered it twice
    assert sum(p["text"].startswith("Queued:") for p in slack.posts) == 1


def test_the_spend_cap_stops_an_upload_before_download(slack_settings):
    trace = slack_settings.out_dir / "earlier" / "trace.jsonl"
    trace.parent.mkdir(parents=True)
    trace.write_text(json.dumps({"ts": jobs.datetime.now(jobs.UTC).isoformat(),
                                 "est_cost_usd": 4.9}) + "\n", encoding="utf-8")  # fmt: skip
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, opener = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(), TEAM)
    assert "of the $5.00 cap" in slack.posts[0]["text"] and opener.requests == []


# --- commands ---------------------------------------------------------------------------------


def command(text, user=USER, channel=CHANNEL):
    return {"command": "/cti", "text": text, "user_id": user, "channel_id": channel,
            "team_id": TEAM, "trigger_id": "t"}  # fmt: skip


def test_help_runs_and_audit(slack_settings):
    bot, slack, _ = aa23_bot(slack_settings)
    said = []
    bot.on_command(command("help"), said.append)
    assert "/cti runs" in said[0] and "&lt;run&gt;" in said[0]
    bot.on_command(command("review 20991231T000000Z-00000000-abcd"), said.append)
    assert "There's no run" in said[-1]
    bot.on_command(command("make me a sandwich"), said.append)
    assert "I don't know that one" in said[-1]

    bot.on_message(upload_event(), TEAM)
    (run_id,) = run_ids(bot.deps.settings)
    bot.on_command(command("runs"), said.append)
    runs = slack.posts[-1]
    assert run_id in json.dumps(runs["blocks"]) and "cti_run_menu" in json.dumps(runs["blocks"])
    bot.on_command(command(f"audit {run_id}"), said.append)
    assert "Hash chain verified" in slack.posts[-1]["blocks"][0]["text"]["text"]


def test_wrong_channel_gets_a_hint_and_strangers_get_nothing(slack_settings):
    bot, slack, _ = make_bot(slack_settings, Fakes())
    said = []
    bot.on_command(command("runs", channel="C0GENERAL1"), said.append)
    bot.on_command(command("runs", user="U0STRANGER"), said.append)
    assert said == ["cti-agent only works in its own private channel."] and slack.posts == []


def fortios_inbox(settings):
    from test_prepatch import inbox_with

    inbox_with(settings, "CVE-2024-21762")


@pytest.fixture
def prepatch_bot(slack_settings, monkeypatch):
    """Pre-patch through the bot, replaying the FortiOS gold case."""
    from test_prepatch import NOW

    from cti_agent.attack.attack_index import AttackIndex
    from cti_agent.pipeline import run_prepatch

    settings = slack_settings.model_copy(update={
        "sources_file": Path(__file__).parents[1] / "data" / "sources.toml",
        "watchlist_file": Path(__file__).parents[1] / "data" / "watchlist.toml",
    })  # fmt: skip
    fortios_inbox(settings)
    attack = AttackIndex(*AA23_ATTACK, FIXTURES / "attack-v20-subset-prepatch.json")
    replay = ReplayClient(FIXTURES / "llm" / "prepatch-CVE-2024-21762")
    monkeypatch.setattr(jobs, "run_prepatch", lambda advisory_id, s, c: run_prepatch(
        advisory_id, s, replay, attack=attack, now=NOW))  # fmt: skip
    return make_bot(settings, replay)


def test_prepatch_top_lists_the_cost_then_runs_on_go_ahead(prepatch_bot):
    bot, slack, _ = prepatch_bot
    bot.on_command(command("prepatch top 3"), lambda text: None)
    offer = slack.posts[-1]
    assert "CVE-2024-21762" in offer["text"] or "CVE-2024-21762" in json.dumps(offer["blocks"])
    assert "About $0.15 each" in json.dumps(offer["blocks"])
    go = offer["blocks"][-1]["elements"][0]
    for _ in range(2):  # a double tap
        bot.on_click(USER, go["action_id"], go["value"], offer["ts"], "trigger")
    assert sum(p["text"].startswith("Queued:") for p in slack.posts) == 1
    sent = slack.sent()
    assert "Exposure: Fortinet" in sent and "Pre-patch hunts ready" in sent
    assert slack.uploads and slack.uploads[0]["filename"].endswith("-brief.md")


def test_fetch_lists_what_to_hunt_with_a_button(slack_settings, monkeypatch):
    from test_prepatch import NOW, RECORDS, FakeOpener

    from cti_agent.feeds.fetch import run_fetch

    settings = slack_settings.model_copy(update={
        "sources_file": Path(__file__).parents[1] / "data" / "sources.toml",
        "watchlist_file": Path(__file__).parents[1] / "data" / "watchlist.toml",
    })  # fmt: skip
    raw = (FIXTURES / "feeds" / "CVE-2024-21762.json").read_bytes()
    result = run_fetch(settings, since=timedelta(hours=1), sources=(),
                       cve_ids=("CVE-2024-21762",),
                       opener=FakeOpener({RECORDS["CVE-2024-21762"]: raw}), now=NOW)  # fmt: skip
    monkeypatch.setattr(jobs, "run_fetch", lambda *a, **k: result)
    bot, slack, _ = make_bot(settings, Fakes())
    bot.on_command(command("fetch 7d"), lambda text: None)
    listing = next(p for p in slack.posts if p["text"].startswith("Fetch:"))
    shown = json.dumps(listing["blocks"])
    assert "CVE-2024-21762" in shown and "cti_prepatch_top" in shown
    assert blocks.validate(listing["blocks"]) == []


# --- review -----------------------------------------------------------------------------------


def find(slack, action_id, after=0):
    """The first posted card with this button, and the button."""
    for post in slack.posts[after:]:
        for block in post["blocks"]:
            for element in block.get("elements", []):
                if element.get("action_id") == action_id:
                    return post, element
    raise AssertionError(f"no {action_id} button was posted")


def click(bot, post, element, user=USER):
    bot.on_click(user, element["action_id"], element["value"], post["ts"], "trigger-1",
                 post["thread_ts"] or post["ts"])  # fmt: skip


def a_card(bot, slack, start, action_id="cti_approve"):
    """A single-item card: the first list's "One by one", then its first card."""
    post, one_by_one = find(slack, "cti_one_by_one", start)
    before = len(slack.posts)
    click(bot, post, one_by_one)
    return find(slack, action_id, before)


def updated(slack, post):
    return [u["blocks"][0]["text"]["text"] for u in slack.updates if u["ts"] == post["ts"]]


@pytest.fixture
def reviewed(slack_settings):
    """The fixture advisory ingested and analysed through the bot, then /cti review."""
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(), TEAM)
    (run_id,) = run_ids(bot.deps.settings)
    start = len(slack.posts)
    bot.on_command(command(f"review {run_id}"), lambda text: None)
    return bot, slack, run_id, start


def decisions(bot, run_id):
    return [(r["item_ref"], r["actor"], r["decision"], r["reason"])
            for r in audit_log_for(bot.deps.settings).entries(run_id)
            if r["action"] == "review"]  # fmt: skip


def test_review_posts_cards_and_a_tap_decides_through_the_gate(reviewed):
    bot, slack, run_id, start = reviewed
    header = slack.posts[start]
    assert header["text"].startswith(f"Review {run_id}")
    assert all(p["thread_ts"] == header["ts"] for p in slack.posts[start + 1 :])
    assert all(blocks.validate(p["blocks"]) == [] for p in slack.posts[start:])
    post, approve = a_card(bot, slack, start)
    click(bot, post, approve)
    assert updated(slack, post)[-1].startswith(f"*Approved* by slack:{USER} (Samuel)")
    ((_, who, decision, _),) = decisions(bot, run_id)
    assert who == f"slack:{USER} (Samuel)" and decision == "approve"
    click(bot, post, approve)  # a second tap
    assert updated(slack, post)[-1].startswith("*Already approved*")
    assert len(decisions(bot, run_id)) == 1


def test_an_old_card_cannot_approve_what_was_edited_since(reviewed):
    from cti_agent.stages.gate import Gate

    bot, slack, run_id, start = reviewed
    post, approve = a_card(bot, slack, start)
    ref = json.loads(approve["value"])["i"]
    terminal = Gate(bot.deps.settings, run_id, "lee", audit_log_for(bot.deps.settings))
    item = terminal.item(ref)
    if item.hunt:
        terminal.edit_hunt(item, item.hunt.draft.query + "\n| take 100")
    else:
        terminal.edit_stix(item, json.dumps(dict(item.stix, description="edited elsewhere")))
    click(bot, post, approve)
    assert "changed after the card was posted" in updated(slack, post)[-1]
    assert decisions(bot, run_id) == []


def test_a_rejection_asks_for_a_reason_and_logs_it(reviewed):
    bot, slack, run_id, start = reviewed
    post, reject = a_card(bot, slack, start, "cti_reject")
    click(bot, post, reject)
    view = slack.views[-1]["view"]
    assert view["callback_id"] == "cti_reject_reason"

    def submitted(reason, user=USER):
        state = {"values": {"reason": {"reason": {"value": reason}}}}
        return {"user": {"id": user, "team_id": TEAM}, "team": {"id": TEAM},
                "view": {**view, "state": state}}  # fmt: skip

    assert "Give a reason" in bot.view_errors(submitted("   "))["reason"]
    bot.on_view(submitted("sinkholed since March"))
    assert "Reason: sinkholed since March" in updated(slack, post)[-1]
    ((_, _, decision, reason),) = decisions(bot, run_id)
    assert (decision, reason) == ("reject", "sinkholed since March")
    bot.on_view(submitted("not allowed", user="U0STRANGER"))
    assert len(decisions(bot, run_id)) == 1


def test_a_list_approves_only_the_set_it_listed(reviewed):
    from cti_agent.stages.gate import Gate

    bot, slack, run_id, start = reviewed
    post, approve_all = find(slack, "cti_approve_kind", start)
    kind = json.loads(approve_all["value"])["k"]
    terminal = Gate(bot.deps.settings, run_id, "lee", audit_log_for(bot.deps.settings))
    first = next(i for i in terminal.pending() if i.kind == kind)
    terminal.decide(first, "reject", "decided in the terminal meanwhile")
    click(bot, post, approve_all)
    assert "Nothing was decided" in updated(slack, post)[-1]
    assert len(decisions(bot, run_id)) == 1

    later = len(slack.posts)
    bot.on_command(command(f"review {run_id}"), lambda text: None)
    post, approve_all = find(slack, "cti_approve_kind", later)
    click(bot, post, approve_all)
    assert updated(slack, post)[-1].startswith("*Approved ")
    assert {d for _, _, d, _ in decisions(bot, run_id)} == {"approve", "reject"}


def test_one_by_one_posts_the_cards_of_a_kind(reviewed):
    bot, slack, _, start = reviewed
    post, one_by_one = find(slack, "cti_one_by_one", start)
    before = len(slack.posts)
    click(bot, post, one_by_one)
    posted = [json.dumps(p["blocks"]) for p in slack.posts[before:]]
    assert posted and all("cti_reject" in p for p in posted)


def test_an_amber_run_is_reviewed_in_the_terminal(slack_settings):
    settings = slack_settings.model_copy(
        update={"slack_approved_for_amber": True, "endpoint_approved_for_amber": True}
    )
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event("ingest tlp:amber+strict"), TEAM)
    (run_id,) = run_ids(settings)
    bot.on_command(command(f"review {run_id}"), lambda text: None)
    assert "Review it in the terminal" in slack.posts[-1]["text"]


# --- publish ----------------------------------------------------------------------------------

WORKSPACE = "11111111-2222-3333-4444-555555555555"


class FakeSentinel:
    def __init__(self, answers=()):
        self.calls, self.answers = [], list(answers)  # then 200 for everything

    def __call__(self, url, body, headers):
        self.calls.append((url, json.loads(body), headers))
        return self.answers.pop(0) if self.answers else (200, {}, b"")


@pytest.fixture
def approved_run(slack_settings, monkeypatch):
    from cti_agent.outputs import sentinel_upload
    from cti_agent.slack import publish
    from cti_agent.stages.gate import Gate

    settings = slack_settings.model_copy(update={"sentinel_workspace_id": WORKSPACE})
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(), TEAM)
    (run_id,) = run_ids(settings)
    gate = Gate(settings, run_id, "sam", audit_log_for(settings))
    for item in list(gate.items):
        if item.kind != "attack-pattern" and not (item.hunt and item.hunt.lint_failed):
            gate.decide(gate.item(item.ref), "approve")
    identities = []

    def token_provider(settings_, use_az_login):
        identities.append(use_az_login)
        return lambda: "SECRET-TOKEN"

    monkeypatch.setattr(publish, "token_provider", token_provider)
    api = FakeSentinel()
    monkeypatch.setattr(sentinel_upload, "urllib_post", api)
    return bot, slack, run_id, api, identities


def submit_publish(bot, slack):
    view = slack.views[-1]["view"]
    bot.on_view({"user": {"id": USER, "team_id": TEAM}, "team": {"id": TEAM}, "view": view})


def test_publish_is_a_dry_run_then_a_confirm_then_the_upload(approved_run):
    bot, slack, run_id, api, identities = approved_run
    start = len(slack.posts)
    bot.on_command(command(f"publish {run_id}"), lambda text: None)
    assert api.calls == [] and "nothing was sent" in json.dumps(slack.posts[start:])
    post, publish_button = find(slack, "cti_publish_confirm", start)
    click(bot, post, publish_button)
    modal = json.dumps(slack.views[-1]["view"])
    assert WORKSPACE in modal and "Upload *" in modal
    submit_publish(bot, slack)
    submit_publish(bot, slack)  # submitted twice: uploaded once, and told so
    assert len(api.calls) == 1 and api.calls[0][2]["Authorization"] == "Bearer SECRET-TOKEN"
    assert identities and not any(identities)  # never az login from Slack
    assert "*Uploaded*" in json.dumps([p["blocks"] for p in slack.posts])
    assert "already queued, running or done" in slack.posts[-1]["text"]
    rows = audit_log_for(bot.deps.settings).entries(run_id)
    slack_actor = f"slack:{USER} (Samuel)"
    published = [(r["action"], r["decision"], r["actor"]) for r in rows
                 if r["action"].startswith("publish")]  # fmt: skip
    assert published == [
        ("publish", "dry-run", slack_actor),
        ("publish_batch", "sent", slack_actor),
        ("publish", "applied", slack_actor),
    ]
    assert "SECRET-TOKEN" not in slack.sent()


def test_approvals_changed_after_the_dry_run_stop_the_upload(approved_run):
    from cti_agent.stages.gate import Gate

    bot, slack, run_id, api, _ = approved_run
    start = len(slack.posts)
    bot.on_command(command(f"publish {run_id}"), lambda text: None)
    post, publish_button = find(slack, "cti_publish_confirm", start)
    click(bot, post, publish_button)
    gate = Gate(bot.deps.settings, run_id, "lee", audit_log_for(bot.deps.settings))
    pattern = next(i for i in gate.pending() if i.kind == "attack-pattern")
    gate.decide(pattern, "approve")  # after the dry run, before the confirm
    submit_publish(bot, slack)
    assert api.calls == []
    assert "changed since you confirmed" in json.dumps(slack.updates)


def test_without_an_identity_there_is_no_publish_button(slack_settings):
    from cti_agent.stages.gate import Gate

    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(), TEAM)
    (run_id,) = run_ids(slack_settings)
    gate = Gate(slack_settings, run_id, "sam", audit_log_for(slack_settings))
    indicator = next(i for i in gate.items if i.kind == "indicator")
    gate.decide(indicator, "approve")
    start = len(slack.posts)
    bot.on_command(command(f"publish {run_id}"), lambda text: None)
    sent = json.dumps(slack.posts[start:])
    assert "Uploading isn't set up here" in sent and "cti_publish_confirm" not in sent


# --- the 29 Oct review's findings, through the bot --------------------------------------------


def test_finding_1_a_list_is_attached_before_its_card_or_offers_no_bulk_approval(
    slack_settings, monkeypatch
):
    monkeypatch.setattr(cards, "LIST_ROOM", 60)  # the fixture's indicators no longer fit
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event(), TEAM)
    (run_id,) = run_ids(bot.deps.settings)
    bot.on_command(command(f"review {run_id}"), lambda text: None)
    post, _ = find(slack, "cti_approve_clean")
    attached = ("upload", f"{run_id}-indicators.txt")
    assert slack.order.index(attached) < slack.order.index(("post", post["ts"]))
    assert "file just above" in post["blocks"][0]["text"]["text"]

    def refuse_uploads(*args):
        raise ConnectionError("Slack refused the file")

    slack.upload_text = refuse_uploads
    start = len(slack.posts)
    bot.on_command(command(f"review {run_id}"), lambda text: None)
    sent = json.dumps(slack.posts[start:])
    assert "cti_approve_clean" not in sent and "can't be approved in one go" in sent


def test_finding_5_the_next_page_skips_nothing_when_earlier_cards_are_decided(
    reviewed, monkeypatch
):
    from cti_agent.stages.gate import Gate, clean_indicator

    monkeypatch.setattr(review, "PAGE", 1)
    bot, slack, run_id, start = reviewed
    post, one_by_one = find(slack, "cti_one_by_one", start)  # the clean indicators
    before = len(slack.posts)
    click(bot, post, one_by_one)
    first, approve_first = find(slack, "cti_approve", before)
    more, next_page = find(slack, "cti_one_by_one", before)
    click(bot, first, approve_first)  # decided before turning the page
    before = len(slack.posts)
    click(bot, more, next_page)
    _, approve_second = find(slack, "cti_approve", before)
    gate = Gate(bot.deps.settings, run_id, "sam", audit_log_for(bot.deps.settings))
    order = [i.ref for i in gate.items if clean_indicator(i)]
    shown = [json.loads(b["value"])["i"] for b in (approve_first, approve_second)]
    assert shown == order[:2]  # the second, not the third


def test_finding_6_a_failed_upload_can_be_confirmed_again(approved_run):
    bot, slack, run_id, api, _ = approved_run
    api.answers = [(403, {}, b"forbidden")]  # the first try fails; then Sentinel accepts
    bot.on_command(command(f"publish {run_id}"), lambda text: None)
    post, publish_button = find(slack, "cti_publish_confirm")
    click(bot, post, publish_button)
    submit_publish(bot, slack)
    assert len(api.calls) == 1 and "Failed" in slack.updates[-1]["text"]
    submit_publish(bot, slack)  # the same confirm, once the cause is fixed
    assert len(api.calls) == 2 and "*Uploaded*" in json.dumps([p["blocks"] for p in slack.posts])


def test_finding_6_a_slack_hiccup_reading_the_file_can_be_retried(slack_settings):
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(slack_settings, Fakes(), file_info("advisory.txt", data), data)
    real = slack.file_info
    calls = []

    def flaky(file_id):
        calls.append(file_id)
        if len(calls) == 1:
            raise ConnectionError("Slack timed out")
        return real(file_id)

    slack.file_info = flaky
    bot.on_message(upload_event(), TEAM)
    assert "Upload it again" in slack.posts[-1]["text"]
    bot.on_message(upload_event(), TEAM)  # Slack delivers it again
    assert any(p["text"].startswith("Queued: ingest") for p in slack.posts)
    assert len(run_ids(bot.deps.settings)) == 1


def test_finding_7_a_slack_error_while_reporting_progress_doesnt_fail_the_upload(approved_run):
    bot, slack, run_id, api, _ = approved_run
    record = slack.update

    def update(channel, ts, blocks_, text):
        if "batch 1 sent" in json.dumps(blocks_):
            raise ConnectionError("Slack is down for a moment")
        record(channel, ts, blocks_, text)

    slack.update = update
    bot.on_command(command(f"publish {run_id}"), lambda text: None)
    post, publish_button = find(slack, "cti_publish_confirm")
    click(bot, post, publish_button)
    submit_publish(bot, slack)
    assert len(api.calls) == 1 and slack.updates[-1]["text"].startswith("Done")
    rows = audit_log_for(bot.deps.settings).entries(run_id)
    assert [r["decision"] for r in rows if r["action"].startswith("publish")][-2:] == [
        "sent", "applied"
    ]  # fmt: skip


def test_finding_8_old_cards_check_the_tlp_again(slack_settings):
    settings = slack_settings.model_copy(
        update={"slack_approved_for_amber": True, "endpoint_approved_for_amber": True}
    )
    data = FIXTURE_REPORT.read_bytes()
    bot, slack, _ = make_bot(settings, Fakes(), file_info("advisory.txt", data), data)
    bot.on_message(upload_event("ingest tlp:amber"), TEAM)
    (run_id,) = run_ids(settings)
    bot.on_command(command(f"review {run_id}"), lambda text: None)
    card, approve = a_card(bot, slack, 0)
    more_post, one_by_one = find(slack, "cti_one_by_one")
    bot.deps.settings = settings.model_copy(update={"slack_approved_for_amber": False})
    click(bot, card, approve)
    assert "can't be shown in this channel" in updated(slack, card)[-1]
    before = len(slack.posts)
    click(bot, more_post, one_by_one)
    (posted,) = slack.posts[before:]  # the refusal, and no cards
    assert "can't be shown in this channel" in posted["text"]
    assert decisions(bot, run_id) == []


def test_finding_9_a_failure_at_a_restricted_tlp_shows_no_detail(slack_settings):
    from cti_agent.outputs.sentinel_upload import PublishError
    from cti_agent.slack.policy import Exposure

    def run(exposure):
        port = FakeSlack()
        deps = Deps(slack_settings, port, {USER: "Samuel"}, client=lambda: None)
        ctx = jobs.Ctx(USER, f"slack:{USER} (Samuel)", CHANNEL, "1.1", "1.1")

        def sentinel_echoes():
            raise PublishError("HTTP 400: indicator 198.51.101.7 in TLP:AMBER report")

        jobs.run_job(deps, ctx, "publish", "publish", sentinel_echoes, exposure)
        return port.sent()

    restricted = run(Exposure.STATUS)
    assert (
        "PublishError" in restricted
        and "198" not in restricted
        and "AMBER report" not in restricted
    )
    assert "198[.]51[.]101[.]7" in run(Exposure.CONTENT)  # where content may be shown
