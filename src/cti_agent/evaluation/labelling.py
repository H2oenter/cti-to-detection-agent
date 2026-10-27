"""Guided labelling: walk a person through a draft's candidates one key at a time.

Each candidate is shown with its page and the text around it; the person reads that part of
the report and decides. Every decision is written to the draft as it's made, so stopping
loses nothing, and a second run picks up at the first undecided candidate. Input is passed
in as functions, as in the review gate, so tests can drive a whole session.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from rich.console import Console
from rich.text import Text

Ask = Callable[[str, list[str]], str]
AskText = Callable[[str, str], str]  # (prompt, default) -> answer

CHOICES = {
    "indicator": {"g": "gold", "o": "optional", "x": "out"},
    "technique": {"g": "required", "o": "optional", "x": "out"},
    "cve": {"g": "keep", "x": "out"},
}
MOVES = {"a": "all the rest gold", "b": "back", "s": "skip for now", "q": "save and stop"}

RULES = {
    "indicator": (
        "Gold: values the report presents as indicators of this activity, in its text. "
        "Optional: defensible either way. Out: placeholders, the authors' contact addresses, "
        "reference links, legitimate tools and services, file names, hostnames."
    ),
    "technique": (
        "Required: behaviour the report attributes to the actors. Optional: what a tool can "
        "do, rather than what the actors were seen doing. Out: anything else."
    ),
    "cve": "Keep: vulnerabilities the report says the actors exploited.",
}
_CISA_ID = re.compile(r"aa\d{2}-\d{3}[a-z]")


@dataclass
class Candidate:
    section: str  # indicator, technique or cve
    kind: str
    value: str
    pages: list[int]
    context: str
    hint: str = ""

    @property
    def key(self) -> str:
        return f"{self.section}:{self.kind}:{self.value}"


@dataclass
class Labelled:
    decided: int
    undecided: int
    stopped: bool

    @property
    def complete(self) -> bool:
        return not self.stopped and self.undecided == 0


def candidates(drafted: dict) -> list[Candidate]:
    """Indicators (those also in the publisher's STIX first), then techniques, then CVEs.
    Values only in the STIX file aren't asked about: the rules leave them out."""
    found = drafted["indicator_candidates"]
    items = [_candidate("indicator", c, "also in CISA's STIX") for c in found["in_text_and_stix"]]
    items += [_candidate("indicator", c) for c in found["text_only"]]
    items += [_candidate("technique", c) for c in drafted["technique_candidates"]]
    items += [_candidate("cve", c) for c in drafted["cve_candidates"]]
    return items


def _candidate(section: str, raw: dict, hint: str = "") -> Candidate:
    return Candidate(section, raw["kind"], raw["value"], raw.get("pages", []),
                     raw.get("context", ""), hint)  # fmt: skip


def run_labelling(
    draft_path: Path,
    console: Console,
    *,
    ask: Ask,
    ask_text: AskText,
    names: Callable[[str], str | None] = lambda attack_id: None,
    include_decided: bool = False,
    today: date | None = None,
) -> Labelled:
    drafted = json.loads(draft_path.read_text(encoding="utf-8"))
    record = drafted.setdefault("labelling", {})
    decisions: dict[str, str] = record.setdefault("decisions", {})
    bulk: list[str] = record.setdefault("bulk", [])  # decided by "all the rest", not one by one
    items = candidates(drafted)
    queue = [c for c in items if include_decided or c.key not in decisions]
    left_out = len(drafted["indicator_candidates"]["stix_only"])
    console.print(
        f"[bold]{drafted['report_id']}[/bold]: {len(items)} candidates, "
        f"{len(items) - len(queue)} already decided. Open {drafted['gold']['source']['file']} "
        "beside this and read each page as it comes up."
    )
    if left_out:
        console.print(f"[dim]{left_out} values only in CISA's STIX are left out: the model "
                      "reads the text, so it can't find them.[/dim]")  # fmt: skip

    position, stopped, section = 0, False, None
    while position < len(queue):
        item = queue[position]
        if item.section != section:
            section = item.section
            console.print(f"\n[bold underline]{section.title()}s[/bold underline]")
            console.print(f"[dim]{RULES[section]}[/dim]")
        console.print(_render(item, position + 1, len(queue), decisions.get(item.key), names))
        choices = CHOICES[item.section]
        menu = "  ".join(f"[{k}] {v}" for k, v in {**choices, **MOVES}.items())
        key = ask(menu, [*choices, *MOVES])
        if key == "q":
            stopped = True
            break
        if key == "b":
            position = max(0, position - 1)
            continue
        if key == "s":
            position += 1
            continue
        if key == "a":
            rest = [c for c in items if c.key not in decisions]
            if not rest:
                console.print("Nothing undecided is left.")
                continue
            if ask(_bulk_question(rest), ["y", "n"]) != "y":
                continue
            for c in rest:
                decisions[c.key] = CHOICES[c.section]["g"]
            bulk.extend(c.key for c in rest)
            _apply(drafted, items, decisions)
            _save(draft_path, drafted)
            console.print(f"[bold]{len(rest)}[/bold] candidates marked gold.")
            break
        decisions[item.key] = choices[key]
        if item.key in bulk:
            bulk.remove(item.key)  # looked at one by one after all
        _apply(drafted, items, decisions)
        _save(draft_path, drafted)
        position += 1

    undecided = sum(c.key not in decisions for c in items)
    if not stopped and not undecided:
        _ask_metadata(drafted, ask_text, today or date.today())
        _save(draft_path, drafted)
    elif undecided:
        console.print(f"\n{undecided} candidates still to decide. Your decisions so far are "
                      "saved; run --label again to carry on.")  # fmt: skip
    return Labelled(len(items) - undecided, undecided, stopped)


def _bulk_question(rest: list[Candidate]) -> str:
    counts = Counter(c.section for c in rest)
    parts = ", ".join(f"{n} {s}{'s' if n > 1 else ''}" for s, n in counts.items())
    return (f"Mark every undecided candidate gold ({parts}), including any skipped, without "
            "seeing them one by one? [y] yes  [n] no")  # fmt: skip


def _render(item: Candidate, position: int, total: int, current: str | None,
            names: Callable[[str], str | None]) -> Text:  # fmt: skip
    title = Text(f"\n[{position}/{total}] ", style="dim")
    title.append(f"{item.kind} ", style="bold")
    title.append(item.value, style="bold cyan")
    if item.section == "technique" and (name := names(item.value)):
        title.append(f"  {name}")
    pages = ", ".join(str(p) for p in item.pages) or "?"
    title.append(f"   page{'s' if len(item.pages) > 1 else ''} {pages}", style="dim")
    if item.hint:
        title.append(f"   ({item.hint})", style="green")
    if current:
        title.append(f"   now: {current}", style="yellow")
    context = Text(f"\n  …{item.context}…", style="dim")
    context.highlight_words([item.value], style="bold cyan", case_sensitive=False)
    return title + context


def _apply(drafted: dict, items: list[Candidate], decisions: dict[str, str]) -> None:
    """Write decisions into the gold section. Entries that aren't candidates (added by hand)
    and candidates not decided yet keep whatever place they had."""
    gold = drafted["gold"]
    decided = [c for c in items if c.key in decisions]
    for section, lists in (("indicator", ("indicators", "optional_indicators")),
                           ("technique", ("techniques", "optional_techniques")),
                           ("cve", ("cves",))):  # fmt: skip
        mine = {_entry_key(section, c.kind, c.value) for c in decided if c.section == section}
        for name in lists:
            gold[name] = [e for e in gold[name] if _entry_key(section, *_kind_value(e)) not in mine]
        for c in decided:
            if c.section != section or decisions[c.key] == "out":
                continue
            target = lists[0] if decisions[c.key] in ("gold", "required", "keep") else lists[1]
            entry = {"kind": c.kind, "value": c.value} if section == "indicator" else c.value
            gold[target].append(entry)


def _kind_value(entry: dict | str) -> tuple[str, str]:
    return (entry["kind"], entry["value"]) if isinstance(entry, dict) else ("", entry)


def _entry_key(section: str, kind: str, value: str) -> tuple[str, str]:
    return (kind if section == "indicator" else "", value.strip().lower())


def _ask_metadata(drafted: dict, ask_text: AskText, today: date) -> None:
    gold = drafted["gold"]
    report_id = drafted["report_id"]
    url = gold["source"].get("url") or (
        f"https://www.cisa.gov/news-events/cybersecurity-advisories/{report_id}"
        if _CISA_ID.fullmatch(report_id) else ""
    )  # fmt: skip
    gold["title"] = ask_text("Report title", gold.get("title", "")).strip()
    gold["source"]["url"] = ask_text("Advisory URL", url).strip() or None
    actors = ask_text("Actors, comma-separated, as the report names them",
                      ", ".join(gold.get("actors", [])))  # fmt: skip
    gold["actors"] = [a.strip() for a in actors.split(",") if a.strip()]
    gold["labelled_by"] = ask_text("Labelled by", gold.get("labelled_by", "")).strip()
    gold["labelled_on"] = ask_text("Labelled on", gold.get("labelled_on") or today.isoformat())
    gold["notes"] = ask_text("Notes for readers of the results (optional)", gold.get("notes", ""))


def _save(path: Path, drafted: dict) -> None:
    path.write_text(json.dumps(drafted, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
