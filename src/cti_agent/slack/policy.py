"""Who may use the bot, where it may post, what each TLP may show, and the daily spend cap."""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from cti_agent.config import Settings, tlp_block_reason
from cti_agent.spend import spent_today

USER_ID = re.compile(r"[UW][A-Z0-9]{2,20}")
CHANNEL_ID = re.compile(r"[CG][A-Z0-9]{2,20}")
# About what each job costs. A job must fit under the cap when it's queued and again
# when it starts, so the most the cap can be overshot by is one job's real cost.
ESTIMATE_USD = {"fetch": 0.0, "publish": 0.0, "ingest": 0.60, "analyse": 0.50, "prepatch": 0.15}


class Exposure(Enum):
    CONTENT = "content"  # defanged values, quotes, titles, KQL and the brief
    STATUS = "status"  # counts and run IDs only
    REFUSE = "refuse"


@dataclass(frozen=True)
class Requester:
    user_id: str
    channel_id: str | None
    team_id: str | None


def parse_users(text: str) -> tuple[dict[str, str], list[str]]:
    """SLACK_USERS: "U...=YourName,U...=Colleague" -> ({id: name}, problems)."""
    users: dict[str, str] = {}
    problems: list[str] = []
    for entry in filter(None, (e.strip() for e in (text or "").split(","))):
        user_id, _, name = (part.strip() for part in entry.partition("="))
        if USER_ID.fullmatch(user_id) and name and len(name) <= 40:
            users[user_id] = name
        else:
            problems.append(f"SLACK_USERS entry {entry!r} isn't MEMBERID=Name")
    return users, problems


def config_problems(settings: Settings) -> list[str]:
    bot = settings.slack_bot_token.get_secret_value() if settings.slack_bot_token else ""
    app = settings.slack_app_token.get_secret_value() if settings.slack_app_token else ""
    problems = []
    if not bot.startswith("xoxb-"):
        problems.append("SLACK_BOT_TOKEN must be the bot token, which starts with xoxb-")
    if not app.startswith("xapp-"):
        problems.append(
            "SLACK_APP_TOKEN must be an app-level token with connections:write (xapp-…)"
        )
    if not CHANNEL_ID.fullmatch(settings.slack_channel_id or ""):
        problems.append("SLACK_CHANNEL_ID must be the private channel's ID (C… or G…)")
    users, user_problems = parse_users(settings.slack_users)
    problems += user_problems
    if not users and not user_problems:
        problems.append("SLACK_USERS must name at least one member allowed to use the bot")
    return problems


def refusal(
    req: Requester, settings: Settings, users: dict[str, str], team_id: str | None
) -> str | None:
    """Why a request is ignored, or None. Callers log the reason with IDs, never the text."""
    if team_id and req.team_id != team_id:
        return "another workspace"
    if req.user_id not in users:
        return "a member not in SLACK_USERS"
    if req.channel_id != settings.slack_channel_id:
        return "another channel"
    return None


def channel_problem(channel: dict) -> str | None:
    """Why the bot mustn't post in this channel (from conversations.info), or None."""
    if not channel.get("is_private"):
        return "SLACK_CHANNEL_ID must be a private channel"
    if channel.get("is_shared") or channel.get("is_ext_shared") or channel.get("is_org_shared"):
        return "the channel is shared beyond this workspace, so the bot won't use it"
    if not channel.get("is_member"):
        return "invite the bot to the channel first: /invite @cti-agent"
    return None


class ChannelGuard:
    """Checks the channel again before posting, at most every `ttl` seconds: a channel that
    was private at startup can be shared later. If the check itself fails, nothing is posted
    until a later check succeeds."""

    def __init__(self, fetch: Callable[[], dict], ttl: float = 300.0,
                 clock: Callable[[], float] = time.monotonic) -> None:  # fmt: skip
        self._fetch, self._ttl, self._clock = fetch, ttl, clock
        self._checked_at: float | None = None
        self._problem: str | None = None
        self._lock = threading.Lock()

    def problem(self) -> str | None:
        with self._lock:
            now = self._clock()
            if self._checked_at is not None and now - self._checked_at < self._ttl:
                return self._problem
            try:
                found = channel_problem(self._fetch())
            except Exception as exc:  # unknown is unsafe; try again next time
                return f"couldn't check the channel ({type(exc).__name__})"
            self._checked_at, self._problem = now, found
            return found


def actor(user_id: str, users: dict[str, str]) -> str:
    """The name the audit log records, always the Slack member, never CTI_AGENT_REVIEWER."""
    return f"slack:{user_id} ({users[user_id]})"


def exposure_for(tlp: str | None, settings: Settings) -> Exposure:
    if tlp in ("CLEAR", "GREEN"):
        return Exposure.CONTENT
    if tlp == "AMBER" and settings.slack_approved_for_amber:
        return Exposure.CONTENT
    if tlp == "RED":
        return Exposure.REFUSE
    return Exposure.STATUS  # AMBER without approval, AMBER+STRICT, or a TLP it doesn't know


def upload_refusal(tlp: str, settings: Settings) -> str | None:
    """Checked before anything is downloaded."""
    if tlp == "RED":
        return "TLP:RED never goes to a third-party model, so it isn't ingested."
    if tlp in ("AMBER", "AMBER+STRICT") and not settings.slack_approved_for_amber:
        return (
            f"This channel isn't approved for TLP:{tlp} (SLACK_APPROVED_FOR_AMBER), so it "
            "isn't ingested here. Use the terminal instead."
        )
    return tlp_block_reason(tlp, settings)


def run_tlp(settings: Settings, run_id: str) -> str | None:
    """The TLP stored with a run, or None if the run isn't known."""
    if not settings.db_path.exists():
        return None
    with closing(sqlite3.connect(settings.db_path)) as conn:
        try:
            row = conn.execute("SELECT tlp FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        except sqlite3.OperationalError:
            return None
    return row[0] if row else None


def spend_refusal(settings: Settings, job: str, now: datetime) -> str | None:
    need = ESTIMATE_USD[job]
    if not need:
        return None
    spent, cap = spent_today(settings.out_dir, now), settings.slack_daily_spend_cap_usd
    if spent + need <= cap:
        return None
    return (
        f"Today's model spend is ${spent:.2f} of the ${cap:.2f} cap, and this needs about "
        f"${need:.2f}. The day resets at 00:00 UTC; the cap is SLACK_DAILY_SPEND_CAP_USD."
    )


def spend_line(settings: Settings, now: datetime) -> str:
    spent = spent_today(settings.out_dir, now)
    return f"today ${spent:.2f} of ${settings.slack_daily_spend_cap_usd:.2f}"
