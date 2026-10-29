"""Block Kit messages. Every builder returns (blocks, text); text is the fallback that phones
show in notifications, so it is made safe in the same way.

Untrusted text only reaches Slack through render.mrkdwn, render.plain or render.code.
validate() checks Slack's limits, measured after escaping and defanging.
"""

from __future__ import annotations

from collections import Counter

from cti_agent.feeds.fetch import FetchResult
from cti_agent.models import AnalysisResult, Hunt, PrepatchResult
from cti_agent.outputs.summary import lint_label, review_scores
from cti_agent.pipeline import IngestResult
from cti_agent.slack.grammar import USAGE
from cti_agent.slack.policy import Exposure
from cti_agent.slack.render import escape, fit, mrkdwn, plain
from cti_agent.slack.values import encode

MAX_BLOCKS = 50
MAX_SECTION = 3000
TOP = 10  # advisories listed after a fetch


# --- primitives ---------------------------------------------------------------------------


def section(text: str, accessory: dict | None = None) -> dict:
    block = {"type": "section", "text": {"type": "mrkdwn", "text": text}}
    return {**block, "accessory": accessory} if accessory else block


def context(text: str) -> dict:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": text}]}


def header(text: str) -> dict:
    return {"type": "header", "text": {"type": "plain_text", "text": plain(text, 150)}}


def button(text: str, action_id: str, value: str, style: str | None = None) -> dict:
    element = {"type": "button", "text": {"type": "plain_text", "text": fit(text, 75)},
               "action_id": action_id, "value": value}  # fmt: skip
    return {**element, "style": style} if style else element


def actions(*elements: dict) -> dict:
    return {"type": "actions", "elements": list(elements)}


def validate(blocks: list[dict]) -> list[str]:
    """Slack's limits; an empty list means the message can be sent."""
    problems = []
    if len(blocks) > MAX_BLOCKS:
        problems.append(f"{len(blocks)} blocks (max {MAX_BLOCKS})")
    for n, block in enumerate(blocks):
        text = (block.get("text") or {}).get("text", "")
        limit = 150 if block["type"] == "header" else MAX_SECTION
        if len(text) > limit:
            problems.append(f"block {n}: {len(text)} characters (max {limit})")
        elements = block.get("elements", []) + [block[k] for k in ("accessory",) if k in block]
        for element in elements:
            if len(element.get("value", "")) > 2000:
                problems.append(f"block {n}: a value over 2000 characters")
            if len(element.get("action_id", "")) > 255:
                problems.append(f"block {n}: an action_id over 255 characters")
            label = element.get("text", "")
            label = label.get("text", "") if isinstance(label, dict) else label
            if element.get("type") == "button" and len(label) > 75:
                problems.append(f"block {n}: a button label over 75 characters")
            if element.get("type") == "mrkdwn" and len(label) > MAX_SECTION:
                problems.append(f"block {n}: a context element over {MAX_SECTION} characters")
            for option in element.get("options", []):
                if len(option.get("value", "")) > 150:
                    problems.append(f"block {n}: a menu value over 150 characters")
        if block["type"] == "context" and len(block["elements"]) > 10:
            problems.append(f"block {n}: more than 10 context elements")
    return problems


# --- jobs ---------------------------------------------------------------------------------


def job_status(title: str, state: str, note: str = "") -> tuple[list[dict], str]:
    """The one message a job edits as it goes. Title and note are already safe."""
    line = f"*{state}:* {title}" + (f"\n{note}" if note else "")
    return [section(fit(line, MAX_SECTION))], fit(f"{state}: {title}", 300)


def help_message() -> tuple[list[dict], str]:
    return [section(escape(USAGE))], "cti-agent commands"


def refused(text: str) -> tuple[list[dict], str]:
    """A refusal written by this code, never quoting Slack or report text."""
    return [section(escape(text))], fit(escape(text), 300)


# --- fetch and pre-patch (feeds are public, so content is shown) -----------------------------


def fetch_message(result: FetchResult, window: str) -> tuple[list[dict], str]:
    tiers = Counter(t.tier for t in result.triaged)
    zero_days = sum(t.zero_day for t in result.triaged)
    summary = (
        f"*Fetch, last {escape(window)}:* {len(result.triaged)} advisories: "
        f"*{tiers['hunt now']} hunt now*, {tiers['hunt soon']} hunt soon ({zero_days} zero-day), "
        f"{tiers['watch']} watch. {len(result.requested)} GET requests, all to allowlisted hosts."
    )
    blocks = [section(summary)]
    top = [t for t in result.triaged if t.passed][:TOP]
    for n, t in enumerate(top, start=1):
        adv = t.advisory
        product = next((f"{p.vendor or p.ecosystem or ''} {p.product}".strip()
                        for p in adv.affected), "unknown product")  # fmt: skip
        fixed = sorted({r.fixed for p in adv.affected for r in p.ranges if r.fixed})
        fix = f"fixed in {', '.join(fixed[:3])}" if fixed else "no fix listed"
        lines = [
            f"*{n}. {mrkdwn(adv.id, 80)}*"
            + (" · *zero-day*" if t.zero_day else "")
            + f" · {t.tier}",
            mrkdwn(f"{product} · CVSS {adv.cvss_score or '?'} · {fix}", 600),
            mrkdwn("Why: " + "; ".join(t.reasons), 1200),
        ]
        blocks.append(section("\n".join(lines)))
    if top:
        n = min(5, len(top))
        blocks.append(actions(button(f"Pre-patch top {n}…", "cti_prepatch_top", encode(n=n))))
    notes = [*result.notes, *(f"skipped: {e}" for e in result.errors[:3])]
    if notes:
        blocks.append(context(mrkdwn("; ".join(notes), 2000)))
    text = f"Fetch: {tiers['hunt now']} hunt now, {tiers['hunt soon']} hunt soon"
    return blocks, text


def prepatch_list(ids: list[str], cost_each: float, spend: str) -> tuple[list[dict], str]:
    """Before spending: which advisories, and what it costs."""
    listed = ", ".join(mrkdwn(i, 80) for i in ids)
    text = (
        f"Pre-patch hunts for {len(ids)} advisories: {listed}.\n"
        f"About ${cost_each:.2f} each in model calls ({escape(spend)})."
    )
    button_ = button("Go ahead", "cti_prepatch_go", encode(ids=ids), style="primary")
    return [section(text), actions(button_)], f"Pre-patch {len(ids)} advisories?"


def _hunt_line(h: Hunt, known: tuple[str, ...] = ()) -> str:
    review = review_scores(h) if h.review or h.second_review else "n/a (written by code)"
    title = mrkdwn(h.draft.title, 300, known)
    line = f"• {title}: lint {escape(lint_label(h))}, review {escape(review)}"
    if h.needs_attention:
        line += f"\n  *Needs a look:* {mrkdwn('; '.join(h.attention_reasons), 600, known)}"
    return line


def prepatch_message(result: PrepatchResult) -> tuple[list[dict], str]:
    adv = result.advisory
    head = (
        f"*{mrkdwn(adv.id, 80)}* {mrkdwn(adv.title or '', 300)} "
        f"({mrkdwn(result.product or 'product not named', 200)})"
        + (f" · {escape(result.tier)}" if result.tier else "")
    )
    lines = [
        head,
        mrkdwn("Why: " + "; ".join(result.signals), 800),
        f"Observables verified against the advisory text: {len(result.observables)}",
    ]
    blocks = [section("\n".join(lines))]
    if result.hunts:
        blocks.append(section(fit("\n".join(_hunt_line(h) for h in result.hunts), MAX_SECTION)))
    blocks.append(context(mrkdwn(result.retire_when, 1500)))
    blocks.append(actions(button("Review", "cti_review", encode(r=result.run_id))))
    return blocks, f"Pre-patch hunts ready for {adv.id}"


# --- a report: ingest, then analyse (what's shown follows the TLP) ------------------------------


def ingest_message(result: IngestResult, tlp: str, exposure: Exposure) -> tuple[list[dict], str]:
    s = result.summary
    accepted, rejected = sum(s.accepted_counts.values()), sum(s.rejected_counts.values())
    stop = f" (stopped: {s.stop_reason})" if s.stop_reason else ""
    head = f"*Ingested* `{escape(s.run_id)}` · TLP:{escape(tlp)} · {escape(s.status)}{escape(stop)}"
    if exposure is Exposure.CONTENT:
        kinds = ", ".join(f"{n} {escape(k)}" for k, n in s.accepted_counts.items()) or "nothing"
        why = ", ".join(f"{n} {escape(k)}" for k, n in s.rejected_counts.items())
        body = f"Accepted, quotes verified: {kinds}.\nRejected: {rejected}" + (
            f" ({why})" if why else ""
        )
    else:
        body = (
            f"{accepted} accepted, {rejected} rejected. Content isn't shown at TLP:{escape(tlp)}."
        )
    note = f"Cost about ${s.est_cost_usd:.3f}."
    return [section(f"{head}\n{body}"), context(note)], f"Ingested {s.run_id}"


def analysis_message(
    analysis: AnalysisResult, exposure: Exposure, known: tuple[str, ...] = ()
) -> tuple[list[dict], str]:
    states = Counter(e.state for e in analysis.coverage)
    attention = sum(h.needs_attention for h in analysis.hunts)
    head = (
        f"*Analysed* `{escape(analysis.run_id)}`: {len(analysis.coverage)} techniques, "
        f"{states['covered']} covered, {states['partial']} partial, {states['gap']} gaps. "
        f"{len(analysis.hunts)} hunts drafted, {attention} need a look."
    )
    blocks = [section(head)]
    if exposure is Exposure.CONTENT:
        if analysis.hunts:
            lines = [
                f"{escape(h.technique_id)} " + _hunt_line(h, known).removeprefix("• ")
                for h in analysis.hunts
            ]
            blocks.append(section(fit("\n".join(f"• {line}" for line in lines), MAX_SECTION)))
        if analysis.leadership_summary:
            label = f"*For leadership* ({escape(analysis.summary_source)}):\n"
            blocks.append(section(label + mrkdwn(analysis.leadership_summary, 2600, known)))
    run = encode(r=analysis.run_id)
    blocks.append(actions(button("Review", "cti_review", run, style="primary"),
                          button("Publish dry run", "cti_publish", run)))  # fmt: skip
    return blocks, f"Analysed {analysis.run_id}: {len(analysis.hunts)} hunts to review"


# --- runs and the audit log ----------------------------------------------------------------


def runs_message(rows: list[dict]) -> tuple[list[dict], str]:
    """rows: run_id, created_at, label (already safe), tlp, status, and counts."""
    if not rows:
        return [section("No runs yet. Upload a report or run `/cti fetch`.")], "No runs yet"
    blocks = [section(f"*Latest {len(rows)} runs*")]
    for row in rows:
        counts = row["counts"]
        text = (
            f"`{escape(row['run_id'])}`\n{row['label']} · TLP:{escape(row['tlp'])} · "
            f"{escape(row['status'])}\n{counts.get('pending', 0)} pending, "
            f"{counts.get('approved', 0)} approved, {counts.get('published', 0)} published"
        )
        menu = {
            "type": "overflow",
            "action_id": "cti_run_menu",
            "options": [
                {"text": {"type": "plain_text", "text": label},
                 "value": encode(r=row["run_id"], a=action)}
                for label, action in (("Review", "review"), ("Publish dry run", "publish"),
                                      ("Audit log", "audit"))
            ],
        }  # fmt: skip
        blocks.append(section(text, accessory=menu))
    return blocks, f"Latest {len(rows)} runs"


def audit_message(
    run_id: str, rows: list[dict], verified: str, exposure: Exposure
) -> tuple[list[dict], str]:
    head = f"*Audit log* `{escape(run_id)}`: {len(rows)} entries. {escape(verified)}"
    if exposure is not Exposure.CONTENT:
        decisions = Counter(f"{r['action']} {r['decision'] or ''}".strip() for r in rows)
        body = ", ".join(f"{n} {escape(k)}" for k, n in decisions.items()) or "nothing yet"
        return [section(f"{head}\n{body}")], f"Audit log for {run_id}"
    lines = []
    for r in rows[-25:]:
        line = f"{r['ts'][:16].replace('T', ' ')} · {r['actor']} · {r['action']}"
        if r["item_ref"]:
            line += f" · {r['item_ref']}"
        if r["decision"]:
            line += f" · {r['decision']}" + (" (bulk)" if r["bulk"] else "")
        if r["reason"]:
            line += f" · {r['reason']}"
        lines.append(mrkdwn(line, 300))
    body = fit("\n".join(lines), MAX_SECTION - len(head) - 1) if lines else "nothing yet"
    return [section(f"{head}\n{body}")], f"Audit log for {run_id}"
