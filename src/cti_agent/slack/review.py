"""Reviewing a run from Slack, through the same gate as the terminal.

The gate is opened fresh for every tap, so it sees what is stored now. A card's tap
decides only if the item still has the hash the card showed; a list's tap only if the
same set is still waiting. A second tap logs nothing. Editing stays in the terminal.

Every tap checks the run's TLP again before it shows or decides anything, so a card
posted while content was allowed can't post more after the setting changes.
"""

from __future__ import annotations

import logging

from cti_agent.audit import AuditChainBroken, audit_log_for
from cti_agent.slack import blocks, cards
from cti_agent.slack.jobs import known_values
from cti_agent.slack.policy import Exposure, actor, exposure_for, run_tlp
from cti_agent.slack.render import defang, defang_code
from cti_agent.stages.gate import Gate, GateError, StaleItem, clean_indicator, listed_digest

log = logging.getLogger(__name__)
PAGE = 10
BULK = ("threat-actor", "vulnerability", "attack-pattern")
GROUPS = ("hunt", "clean", "flagged", *BULK)


def open_gate(bot, user: str, run_id: str) -> Gate | str:
    settings = bot.deps.settings
    try:
        return Gate(settings, run_id, actor(user, bot.deps.users), audit_log_for(settings))
    except AuditChainBroken as exc:
        return f"The audit log failed verification, so no decisions can be made: {exc}"
    except GateError as exc:
        return str(exc)


def shown_here(bot, run_id: str) -> bool:
    settings = bot.deps.settings
    return exposure_for(run_tlp(settings, run_id), settings) is Exposure.CONTENT


def not_shown_here(run_id: str) -> str:
    return (f"Run {run_id} can't be shown in this channel at its TLP. Review it in the "
            f"terminal: cti-agent review {run_id}")  # fmt: skip


def belongs(group: str, item) -> bool:
    if group == "clean":
        return clean_indicator(item)
    if group == "flagged":
        return item.kind == "indicator" and not clean_indicator(item)
    return item.kind == group


def groups(gate: Gate) -> dict[str, list]:
    pending = gate.pending()
    return {group: [i for i in pending if belongs(group, i)] for group in GROUPS}


def post_review(bot, user: str, run_id: str) -> None:
    if not shown_here(bot, run_id):
        bot.say(blocks.refused(not_shown_here(run_id)))
        return
    gate = open_gate(bot, user, run_id)
    if isinstance(gate, str):
        bot.say(blocks.refused(gate))
        return
    found = groups(gate)
    if not any(found.values()):
        bot.say(blocks.refused(f"Nothing in {run_id} is waiting for review."))
        return
    known = known_values(bot.deps.settings, run_id)
    counts = {"hunt": len(found["hunt"]),
              "indicator": len(found["clean"]) + len(found["flagged"]),
              **{kind: len(found[kind]) for kind in BULK}}  # fmt: skip
    thread = bot.say(cards.review_header(run_id, counts, len(found["clean"])))
    post_page(bot, gate, run_id, "hunt", None, thread, known)
    if items := found["clean"]:
        attached = _attach_if_cut(bot, run_id, "indicators", items, known, thread)
        card = cards.clean_list_card(run_id, items, listed_digest(items), known, attached)
        bot.say(card, thread)
    post_page(bot, gate, run_id, "flagged", None, thread, known)
    for kind in BULK:
        if items := found[kind]:
            name = cards.plural(kind, 2).replace(" ", "-")
            attached = _attach_if_cut(bot, run_id, name, items, known, thread)
            card = cards.kind_list_card(run_id, kind, items, listed_digest(items), known, attached)
            bot.say(card, thread)


def post_page(bot, gate: Gate, run_id: str, group: str, after: str | None, thread: str,
              known: tuple[str, ...] | None = None) -> None:  # fmt: skip
    """The next PAGE waiting cards of a group, after the last item already shown. Paging by
    item rather than by position means a decision between pages can't skip anything."""
    known = known if known is not None else known_values(bot.deps.settings, run_id)
    ordered = [i for i in gate.items if belongs(group, i)]  # a fixed order, decided or not
    waiting = {i.ref for i in gate.pending()}
    start = next((n + 1 for n, i in enumerate(ordered) if i.ref == after), 0) if after else 0
    upcoming = [i for i in ordered[start:] if i.ref in waiting]
    for item in upcoming[:PAGE]:
        post_card(bot, gate, run_id, item, known, thread)
    if len(upcoming) > PAGE:
        last = upcoming[PAGE - 1].ref
        bot.say(cards.more_button(run_id, group, last, len(upcoming) - PAGE), thread)


def post_card(bot, gate: Gate, run_id: str, item, known, thread: str) -> None:
    status = gate.status(item)
    if not item.hunt:
        bot.say(cards.stix_card(run_id, item, status, known), thread)
        return
    _, complete = cards.query_preview(item.hunt.draft.query, known)
    attached = False
    if not complete:  # the whole query goes up first, so the card can point to it
        header = (f"// Defanged for Slack. The runnable file is "
                  f"out/{run_id}/hunts/{item.hunt.draft_id}.kql\n")  # fmt: skip
        body = header + defang_code(item.hunt.draft.query, known)
        attached = _upload(bot, thread, f"{item.hunt.draft_id}.kql", body,
                           f"{item.hunt.technique_id} query")  # fmt: skip
    bot.say(cards.hunt_card(run_id, item, status, known, attached), thread)


def _attach_if_cut(bot, run_id, name, items, known, thread) -> bool:
    """Post the whole list as a file when the card can't show all of it; True if the file
    went up. A list the card shows whole needs no file."""
    if cards.list_items(items, known).complete:
        return False
    text = "\n".join(defang(i.label, known) for i in items)
    return _upload(bot, thread, f"{run_id}-{name}.txt", text, name)


def _upload(bot, thread: str, filename: str, content: str, title: str) -> bool:
    try:
        bot.deps.port.upload_text(bot.channel, thread, filename, content, title)
    except Exception:  # without the file, the card mustn't offer approval
        log.warning("couldn't attach %s; the card won't offer approval", filename, exc_info=True)
        return False
    return True


def next_page(bot, user: str, data: dict, thread: str) -> None:
    if not shown_here(bot, data["r"]):
        bot.say(blocks.refused(not_shown_here(data["r"])), thread)
        return
    gate = open_gate(bot, user, data["r"])
    if isinstance(gate, str):
        bot.say(blocks.refused(gate), thread)
        return
    if (group := data.get("k", "")) in GROUPS:
        post_page(bot, gate, data["r"], group, data.get("i"), thread)


# --- decisions -----------------------------------------------------------------------------


def decide_card(bot, user, data, decision, reason, message_ts) -> None:
    """One item, from its card. The card is replaced by what happened."""
    port, channel = bot.deps.port, bot.channel
    if not shown_here(bot, data["r"]):
        port.update(channel, message_ts, *blocks.refused(not_shown_here(data["r"])))
        return
    gate = open_gate(bot, user, data["r"])
    if isinstance(gate, str):
        port.update(channel, message_ts, *blocks.refused(gate))
        return
    known = known_values(bot.deps.settings, data["r"])
    try:
        item = gate.item(data["i"])
        decided = gate.decide(item, decision, reason, expected_hash=data["h"],
                              only_if_undecided=True)  # fmt: skip
    except StaleItem:
        port.update(channel, message_ts, *blocks.refused(
            "This item changed after the card was posted, so nothing was decided. "
            f"Run /cti review {data['r']} again to see the current version."))  # fmt: skip
        return
    except GateError as exc:
        port.update(channel, message_ts, *blocks.refused(f"Nothing was decided: {exc}"))
        return
    if not decided:
        latest = gate.audit.latest_decisions(gate.run_id)[item.ref]
        port.update(channel, message_ts, *cards.decided_card(
            item.label, latest["decision"], latest["actor"], latest["reason"], known,
            already=True))  # fmt: skip
        return
    port.update(channel, message_ts,
                *cards.decided_card(item.label, decision, gate.actor, reason, known))  # fmt: skip


def decide_list(bot, user, data, decision, reason, message_ts) -> None:
    """A listed set, from its card: only if it's still exactly the set that was listed."""
    port, channel = bot.deps.port, bot.channel
    if not shown_here(bot, data["r"]):
        port.update(channel, message_ts, *blocks.refused(not_shown_here(data["r"])))
        return
    gate = open_gate(bot, user, data["r"])
    if isinstance(gate, str):
        port.update(channel, message_ts, *blocks.refused(gate))
        return
    kind = data.get("k", "")
    try:
        if kind == "clean" and decision == "approve":
            count = gate.approve_clean_indicators(digest=data["d"])
        elif kind in BULK:
            waiting = [i for i in gate.pending() if i.kind == kind]
            if not waiting:
                raise GateError(f"no {cards.plural(kind, 2)} are waiting any more")
            count = gate.decide_rest_of_type(waiting[0], decision, reason, digest=data["d"])
        else:
            raise GateError("that list can't be decided in one go")
    except GateError as exc:
        port.update(channel, message_ts, *blocks.refused(f"Nothing was decided: {exc}"))
        return
    port.update(channel, message_ts,
                *cards.list_decided(count, kind, decision, gate.actor, reason))  # fmt: skip
