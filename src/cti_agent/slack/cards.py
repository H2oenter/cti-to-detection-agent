"""Review cards, the reject and publish modals, and the publish messages.

Each card carries what the person saw (the item's ref, hash and status, or a digest of a
list), so a tap on an old card can't decide on something that has changed since.

Nothing is approved unseen. What a card shows is measured after escaping and defanging:
- a list is never cut mid-item, and when it can't all be shown, the full list is attached
  as a file first; if that fails, the list gets no bulk button;
- a query that doesn't fit is attached whole the same way, or the hunt can't be approved here;
- warnings, lint findings and "needs a look" come first on a card, and if even that part is
  too long for Slack, the card has no Approve button.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from cti_agent.outputs.sentinel_hunting import FOLDER as TEMPLATE_FOLDER
from cti_agent.outputs.summary import review_scores
from cti_agent.slack.blocks import MAX_SECTION, actions, button, context, section
from cti_agent.slack.render import code, escape, fit, mrkdwn
from cti_agent.slack.values import encode

KIND_NAMES = {"hunt": "hunt", "indicator": "indicator", "threat-actor": "threat actor",
              "vulnerability": "vulnerability", "attack-pattern": "attack pattern"}  # fmt: skip
MAX_BULK = 200  # longer lists get no bulk button: too long to check on a phone
QUERY_LINES = 25
QUERY_ROOM = 2700  # rendered characters of query on a card
LIST_ROOM = MAX_SECTION - 400  # rendered characters of list; the rest is the head and a pointer
WHOLE = 10**6  # no cap: a part that must be shown whole, or not at all


def plural(kind: str, n: int) -> str:
    name = KIND_NAMES.get(kind, kind)
    return name if n == 1 else name + "s"


def confirm(title: str, text: str, yes: str) -> dict:
    return {
        "title": {"type": "plain_text", "text": fit(title, 100)},
        "text": {"type": "mrkdwn", "text": fit(text, 300)},
        "confirm": {"type": "plain_text", "text": fit(yes, 30)},
        "deny": {"type": "plain_text", "text": "Cancel"},
    }


def terminal_only(run_id: str) -> str:
    return (f"It can't all be shown on a card, so it can't be approved here. Use the terminal: "
            f"`cti-agent review {escape(run_id)}`")  # fmt: skip


def review_header(run_id: str, counts: dict[str, int], clean: int) -> tuple[list[dict], str]:
    parts = [f"{n} {plural(kind, n)}" for kind, n in counts.items() if n]
    text = (
        f"*Review* `{escape(run_id)}`: {', '.join(parts)} waiting"
        + (f" ({clean} of the indicators passed both checks)" if clean else "")
        + ". The cards are in this thread. Editing stays in the terminal."
    )
    return [section(text)], f"Review {run_id}: {sum(counts.values())} items waiting"


def _decision_buttons(run_id: str, item, status: str, approve: bool) -> list[dict]:
    value = encode(r=run_id, i=item.ref, h=item.hash, s=status)
    buttons = [button("Approve", "cti_approve", value, style="primary")] if approve else []
    buttons.append(button("Reject…", "cti_reject", value, style="danger"))
    return buttons


# --- one item -----------------------------------------------------------------------------


def query_preview(query: str, known: tuple[str, ...]) -> tuple[str, bool]:
    """The query's first whole lines that fit on a card once rendered, and whether that's
    all of it."""
    lines = (query or "").splitlines()
    shown: list[str] = []
    for line in lines[:QUERY_LINES]:
        if len(code("\n".join([*shown, line]), WHOLE, known)) > QUERY_ROOM:
            break
        shown.append(line)
    if not shown and lines:  # the first line alone is too long
        return code(lines[0], QUERY_ROOM, known), False
    return code("\n".join(shown), QUERY_ROOM, known), len(shown) == len(lines)


def hunt_card(
    run_id: str, item, status: str, known: tuple[str, ...], attached: bool = False
) -> tuple[list[dict], str]:
    """`attached`: the whole query was posted as a file just before this card."""
    hunt, draft = item.hunt, item.hunt.draft
    head = [
        f"*Hunt* · {escape(hunt.technique_id)} · {mrkdwn(draft.title, WHOLE, known)}",
        f"Tables: {mrkdwn(', '.join(draft.tables), WHOLE, known)}",
    ]
    if hunt.needs_attention:
        head.append(f"*Needs a look:* {mrkdwn('; '.join(hunt.attention_reasons), WHOLE, known)}")
    head += [f"Lint {f.severity}: {escape(f.code)}: {mrkdwn(f.message, WHOLE, known)}"
             for f in hunt.lint]  # fmt: skip
    if hunt.retire_when:
        head.append(mrkdwn(hunt.retire_when, WHOLE))
    review = review_scores(hunt) if hunt.review or hunt.second_review else "n/a (written by code)"
    detail = [
        f"Confidence {draft.confidence.score}/100 · review (faithful/KQL/actionable/calibrated): "
        f"{escape(review)}",
        *(f"Evidence: {mrkdwn(q, 300, known)}" for q in draft.evidence_quotes[:3]),
    ]
    for scores, who in ((hunt.review, "First reviewer"), (hunt.second_review, "Second reviewer")):
        if scores:
            detail += [f"{who}: {mrkdwn(reason, 250, known)}" for reason in scores.reasons[:3]]
    preview, complete = query_preview(draft.query, known)
    if not complete:
        lines = len(draft.query.splitlines())
        preview += (f"\nThe whole query ({lines} lines) is in the file just above." if attached
                    else "\nThe rest of the query isn't shown here.")  # fmt: skip
    head_text, detail_text = "\n".join(head), "\n".join(detail)
    whole = len(head_text) <= MAX_SECTION and len(detail_text) <= MAX_SECTION
    card = [section(fit(head_text, MAX_SECTION)), section(fit(detail_text, MAX_SECTION)),
            section(preview)]  # fmt: skip
    if hunt.lint_failed:
        terminal = f"`cti-agent review {escape(run_id)}`"
        card.append(context(f"Lint errors stop approval. Edit it in the terminal: {terminal}"))
    elif not whole or not (complete or attached):
        card.append(context(terminal_only(run_id)))
    approve = not hunt.lint_failed and whole and (complete or attached)
    card.append(actions(*_decision_buttons(run_id, item, status, approve)))
    return card, f"Hunt to review: {hunt.technique_id}"


def stix_card(run_id: str, item, status: str, known: tuple[str, ...]) -> tuple[list[dict], str]:
    obj, name = item.stix, KIND_NAMES[item.kind].capitalize()
    head = [f"*{name}* · {mrkdwn(item.label, WHOLE, known)}"]
    head += [f"*Warning:* {mrkdwn(w, WHOLE, known)}" for w in obj.get("x_cti_agent_warnings", [])]
    if "pattern" in obj:
        head.append(f"Pattern: {mrkdwn(obj['pattern'], WHOLE, known)}")
    if obj.get("aliases"):
        head.append(f"Aliases: {mrkdwn(', '.join(obj['aliases']), WHOLE, known)}")
    if obj.get("description"):
        head.append(f"Description: {mrkdwn(obj['description'], WHOLE, known)}")
    if obj.get("x_cti_agent_recheck_role"):
        head.append(f"Re-check: {escape(obj['x_cti_agent_recheck_role'].replace('_', ' '))}")
    head_text = "\n".join(head)
    whole = len(head_text) <= MAX_SECTION
    card = [section(fit(head_text, MAX_SECTION))]
    if quote := obj.get("x_cti_agent_evidence_quote"):
        page = obj.get("x_cti_agent_evidence_page")
        where = obj.get("x_cti_agent_evidence_kind", "") + (f", page {page}" if page else "")
        card.append(section(f"Evidence ({escape(where)}): {mrkdwn(quote, 800, known)}"))
    if not whole:
        card.append(context(terminal_only(run_id)))
    card.append(actions(*_decision_buttons(run_id, item, status, whole)))
    return card, f"{name} to review"


# --- lists --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Listed:
    text: str
    shown: int
    total: int

    @property
    def complete(self) -> bool:
        return self.shown == self.total


def list_items(items, known: tuple[str, ...], room: int | None = None) -> Listed:
    """As many whole lines as fit once rendered: an item is listed in full or not at all."""
    room = LIST_ROOM if room is None else room
    lines: list[str] = []
    used = 0
    for item in items:
        warned = (item.stix or {}).get("x_cti_agent_warnings")
        line = f"• {mrkdwn(item.label, WHOLE, known)}" + (" · *warning*" if warned else "")
        if used + len(line) + 1 > room:
            break
        lines.append(line)
        used += len(line) + 1
    return Listed("\n".join(lines), len(lines), len(items))


def _pointer(listed: Listed, attached: bool) -> str:
    if listed.complete:
        return ""
    more = listed.total - listed.shown
    if attached:
        return f"\n…and {more} more: every item is in the file just above."
    return f"\n…and {more} more not shown here, so they can't be approved in one go."


def clean_list_card(run_id: str, items, digest: str, known: tuple[str, ...],
                    attached: bool = False):  # fmt: skip
    """`attached`: the whole list was posted as a file just before this card."""
    n = len(items)
    listed = list_items(items, known)
    head = (f"*{n} {plural('indicator', n)} passed both checks* (the validator and the "
            "re-check, with no warning):")  # fmt: skip
    text = f"{head}\n{listed.text}{_pointer(listed, attached)}"
    one_by_one = button("One by one", "cti_one_by_one", encode(r=run_id, k="clean"))
    if n > MAX_BULK or not (listed.complete or attached):
        blocks = [section(text)]
        if n > MAX_BULK:
            blocks.append(context("Too many to approve as one list on a phone: go one by one, "
                                  "or use the terminal."))  # fmt: skip
        return [*blocks, actions(one_by_one)], f"{n} indicators"
    value = encode(r=run_id, k="clean", d=digest, n=n)
    approve = button(f"Approve these {n}", "cti_approve_clean", value, style="primary")
    approve["confirm"] = confirm(
        f"Approve {n} {plural('indicator', n)}?", "Each is logged under your name.", "Approve"
    )
    return [section(text), actions(approve, one_by_one)], f"{n} indicators"


def kind_list_card(run_id: str, kind: str, items, digest: str, known: tuple[str, ...],
                   attached: bool = False):  # fmt: skip
    n = len(items)
    listed = list_items(items, known)
    warned = sum(bool((i.stix or {}).get("x_cti_agent_warnings")) for i in items)
    note = f" ({warned} with a warning)" if warned else ""
    text = f"*{n} {plural(kind, n)}* waiting{note}:\n{listed.text}{_pointer(listed, attached)}"
    value = encode(r=run_id, k=kind, d=digest, n=n)
    buttons = []
    if n <= MAX_BULK and (listed.complete or attached):
        approve = button(f"Approve all {n}", "cti_approve_kind", value, style="primary")
        approve["confirm"] = confirm(
            f"Approve all {n} {plural(kind, n)}?", "Each is logged under your name.", "Approve"
        )
        buttons.append(approve)
    buttons += [
        button(f"Reject all {n}…", "cti_reject_kind", value, style="danger"),
        button("One by one", "cti_one_by_one", encode(r=run_id, k=kind)),
    ]
    return [section(text), actions(*buttons)], f"{n} {plural(kind, n)}"


def more_button(run_id: str, kind: str, after_ref: str, left: int) -> tuple[list[dict], str]:
    """The next page starts after the last item shown, so decided items can't shift it."""
    value = encode(r=run_id, k=kind, i=after_ref)
    return [actions(button(f"Next {min(left, 10)} of {left}", "cti_one_by_one", value))], "More"


# --- after a decision ------------------------------------------------------------------------


def decided_card(
    label: str, decision: str, who: str, reason: str | None, known: tuple[str, ...],
    already: bool = False,
) -> tuple[list[dict], str]:  # fmt: skip
    verb = "Approved" if decision == "approve" else "Rejected"
    head = f"Already {verb.lower()}" if already else verb
    text = f"*{head}* by {escape(who)}: {mrkdwn(label, 300, known)}"
    if reason:
        text += f"\nReason: {mrkdwn(reason, 500, known)}"
    return [section(text)], f"{verb} by {who}"


def list_decided(count: int, kind: str, decision: str, who: str, reason: str | None):
    verb = "Approved" if decision == "approve" else "Rejected"
    name = plural("indicator" if kind == "clean" else kind, count)
    text = f"*{verb} {count} {name}* by {escape(who)}, each logged on its own line."
    if reason:
        text += f"\nReason: {mrkdwn(reason, 500)}"
    return [section(text)], f"{verb} {count} {name}"


def reject_modal(metadata: str, what: str) -> dict:
    return {
        "type": "modal",
        "callback_id": "cti_reject_reason",
        "private_metadata": metadata,
        "title": {"type": "plain_text", "text": "Reject"},
        "submit": {"type": "plain_text", "text": "Reject"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            section(f"Rejecting {what}. Your reason goes in the audit log."),
            {
                "type": "input",
                "block_id": "reason",
                "label": {"type": "plain_text", "text": "Reason"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "reason",
                    "multiline": True,
                    "min_length": 1,
                    "max_length": 500,
                },
            },
        ],
    }


# --- publishing --------------------------------------------------------------------------------


def dry_run_message(run_id: str, dry, not_ready: str | None) -> tuple[list[dict], str]:
    plan = dry.plan
    counts = ", ".join(f"{n} {escape(k)}" for k, n in sorted(plan.counts().items()))
    lines = [
        f"*Dry run* `{escape(run_id)}`: nothing was sent.",
        f"It would send {len(plan.objects)} objects ({counts}) in {len(plan.batches)} request(s).",
    ]
    lines += [
        f"Left out: {n} {escape(kind)} (Sentinel's upload API doesn't accept them)"
        for kind, n in Counter(s["type"] for s in plan.skipped).items()
    ]
    if plan.hunts_not_uploaded:
        lines.append(f"{plan.hunts_not_uploaded} approved hunt(s) stay in `approved/hunts/` for "
                     f"your change process, with templates for Sentinel Repositories in "
                     f"`approved/{TEMPLATE_FOLDER}/`; hunts are never uploaded.")  # fmt: skip
    folder = f"out/{escape(run_id)}/publish/{escape(dry.folder.name)}/"
    lines.append(f"The exact requests are in `{folder}`.")
    message = [section("\n".join(lines))]
    if not_ready:
        message.append(context(f"Uploading isn't set up here: {mrkdwn(not_ready, 600)}"))
    else:
        n = len(plan.objects)
        value = encode(r=run_id, d=dry.digest, n=n)
        message.append(actions(button(f"Publish {n}…", "cti_publish_confirm", value,
                                      style="danger")))  # fmt: skip
    return message, f"Dry run for {run_id}: {len(plan.objects)} objects"


def publish_modal(metadata: str, n: int, requests: int, workspace: str) -> dict:
    text = (
        f"Upload *{n} objects* in {requests} request(s) to Sentinel workspace "
        f"`{escape(workspace)}`?\nOnly what was approved, unchanged since the dry run. Each "
        "batch is written to the audit log."
    )
    return {
        "type": "modal",
        "callback_id": "cti_publish_upload",
        "private_metadata": metadata,
        "title": {"type": "plain_text", "text": "Publish to Sentinel"},
        "submit": {"type": "plain_text", "text": "Upload"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [section(text)],
    }


def upload_message(run_id: str, uploaded) -> tuple[list[dict], str]:
    sent = len(uploaded.plan.objects) - len(uploaded.failed)
    text = (
        f"*Uploaded* {sent} objects from `{escape(run_id)}` to Sentinel; "
        f"{len(uploaded.failed)} rejected by Sentinel. `/cti audit {escape(run_id)}` lists each "
        "batch."
    )
    return [section(text)], f"Uploaded {sent} objects to Sentinel"
