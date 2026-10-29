"""The fixed command grammar: `/cti …` and the comment on an uploaded report.

Code decides what a message means; no model ever reads Slack text. Anything outside the
grammar is refused with the usage line.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import timedelta

from cti_agent.feeds.fetch import parse_since

MAX_TEXT = 300
MAX_WINDOW = timedelta(days=30)
RUN_ID = re.compile(r"\d{8}T\d{6}Z-[A-Za-z0-9_-]{1,80}-[0-9a-f]{4}")
ADVISORY_ID = re.compile(
    r"CVE-\d{4}-\d{4,7}|GHSA(-[0-9a-z]{4}){3}|[A-Z]{2,10}-[A-Za-z0-9._-]{2,60}"
)
WINDOW = re.compile(r"\d{1,4}[mhd]")
TLPS = {"clear": "CLEAR", "green": "GREEN", "amber": "AMBER", "amber+strict": "AMBER+STRICT",
        "red": "RED"}  # fmt: skip
# Phones turn hyphens into dashes; IDs are typed with hyphens.
_DASHES = dict.fromkeys((0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212), "-")

USAGE = (
    "Commands: `/cti help`, `/cti runs`, `/cti fetch [24h|7d]`, `/cti prepatch top 5`, "
    "`/cti prepatch CVE-2024-21762`, `/cti analyse <run>`, `/cti review <run>`, "
    "`/cti publish <run>`, `/cti audit <run>`. To ingest a report, upload it to this "
    "channel with the comment `ingest tlp:clear` (or green, amber, amber+strict)."
)


@dataclass(frozen=True)
class Help:
    pass


@dataclass(frozen=True)
class Runs:
    pass


@dataclass(frozen=True)
class Fetch:
    window: str = "24h"


@dataclass(frozen=True)
class PrepatchTop:
    n: int


@dataclass(frozen=True)
class PrepatchOne:
    advisory_id: str


@dataclass(frozen=True)
class Analyse:
    run_id: str


@dataclass(frozen=True)
class Review:
    run_id: str


@dataclass(frozen=True)
class Publish:
    run_id: str


@dataclass(frozen=True)
class Audit:
    run_id: str


@dataclass(frozen=True)
class Ingest:
    tlp: str


@dataclass(frozen=True)
class Invalid:
    message: str


Command = (
    Help | Runs | Fetch | PrepatchTop | PrepatchOne | Analyse | Review | Publish | Audit | Invalid
)
ON_A_RUN = {"analyse": Analyse, "analyze": Analyse, "review": Review, "publish": Publish,
            "audit": Audit}  # fmt: skip


def _words(text: str) -> list[str] | None:
    text = unicodedata.normalize("NFKC", text or "").translate(_DASHES).strip()
    return None if len(text) > MAX_TEXT else text.split()


def advisory_id(text: str) -> str | None:
    candidate = "CVE-" + text[4:] if text.lower().startswith("cve-") else text
    return candidate if ADVISORY_ID.fullmatch(candidate) else None


def parse_command(text: str) -> Command:
    words = _words(text)
    if words is None:
        return Invalid(f"That's longer than any command. {USAGE}")
    if not words or [w.lower() for w in words] == ["help"]:
        return Help()
    verb, args = words[0].lower(), words[1:]
    if verb == "runs" and not args:
        return Runs()
    if verb == "fetch" and len(args) <= 1:
        window = (args or ["24h"])[0].lower()
        if WINDOW.fullmatch(window) and parse_since(window) <= MAX_WINDOW:
            return Fetch(window)
        return Invalid("`fetch` takes a window of up to 30 days, such as `24h` or `7d`.")
    if verb == "prepatch":
        if len(args) == 2 and args[0].lower() == "top" and args[1].isdigit():
            if 1 <= int(args[1]) <= 10:
                return PrepatchTop(int(args[1]))
        elif len(args) == 1 and (found := advisory_id(args[0])):
            return PrepatchOne(found)
        return Invalid("`prepatch` takes `top N` (1 to 10) or one CVE or GHSA ID.")
    if verb in ON_A_RUN:
        if len(args) == 1 and RUN_ID.fullmatch(args[0]):
            return ON_A_RUN[verb](args[0])
        return Invalid(f"`{verb}` takes one run ID; `/cti runs` lists them with buttons.")
    return Invalid(f"I don't know that one. {USAGE}")


def parse_upload_comment(text: str) -> Ingest | Invalid | None:
    """None when the comment isn't for the bot (people share other files too)."""
    words = _words(text)
    if not words or words[0].lower() != "ingest":
        return None
    word = words[1].lower() if len(words) == 2 else ""
    if word.startswith("tlp:") and (tlp := TLPS.get(word[4:])):
        return Ingest(tlp)
    return Invalid(
        "Say the report's TLP: `ingest tlp:clear` (or green, amber, amber+strict). "
        "There's no default: TLP is yours to declare."
    )
