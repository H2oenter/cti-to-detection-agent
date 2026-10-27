"""The interactive side of the gate: show one item, take one key, apply it.

Input and editing are passed in as functions, so tests can drive a whole session.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cti_agent.stages.gate import BULK_KINDS, Gate, GateError, ReviewItem, clean_indicator

Ask = Callable[[str, list[str]], str]
AskText = Callable[[str], str]
Edit = Callable[[str, str], str | None]


def run_review(
    gate: Gate,
    console: Console,
    *,
    ask: Ask,
    ask_text: AskText,
    edit: Edit,
    include_decided: bool = False,
) -> Counter:
    counts: Counter = Counter()
    queue = [i.ref for i in gate.pending(include_decided)]
    position = 0
    while position < len(queue):
        item = gate.item(queue[position])
        status = gate.status(item)
        if not include_decided and status not in ("pending", "changed"):
            position += 1  # decided by a "rest of type" choice earlier in this session
            continue
        console.print(render_item(item, status, position + 1, len(queue)))
        clean = gate.clean_indicators() if clean_indicator(item) else []
        keys = ["a", "r", "e", "s", "q"] + (["A", "R"] if item.kind in BULK_KINDS else [])
        prompt = "[a]pprove [r]eject [e]dit [s]kip [q]uit" + (
            " | [A]pprove or [R]eject every remaining " + item.kind if item.kind in BULK_KINDS
            else ""
        )  # fmt: skip
        if clean:
            keys.append("A")
            prompt += f" | [A]pprove all {len(clean)} indicators that passed both checks"
        key = ask(prompt, keys)
        if key == "A" and clean:
            console.print(indicator_table(clean))
            if ask(f"Approve these {len(clean)} indicators?", ["y", "n"]) == "y":
                try:
                    done = gate.approve_clean_indicators([i.ref for i in clean])
                    counts["approved"] += done
                    console.print(f"[bold]{done}[/bold] indicators: approved (logged one by one)")
                    position += 1
                except GateError as exc:
                    console.print(f"[red]{exc}[/red]")
            continue
        try:
            if key == "q":
                break
            if key == "s":
                counts["skipped"] += 1
            elif key == "a":
                gate.decide(item, "approve")
                counts["approved"] += 1
            elif key == "r":
                gate.decide(item, "reject", ask_text("Reason for rejecting"))
                counts["rejected"] += 1
            elif key in ("A", "R"):
                decision = "approve" if key == "A" else "reject"
                reason = ask_text("Reason for rejecting all of them") if key == "R" else None
                done = gate.decide_rest_of_type(item, decision, reason)
                counts["approved" if key == "A" else "rejected"] += done
                console.print(
                    f"[bold]{done}[/bold] {item.kind} items: {decision}d (logged one by one)"
                )
            elif key == "e":
                _edit(gate, item, edit, console)
                continue  # show the edited item again before deciding
            position += 1
        except GateError as exc:
            console.print(f"[red]{exc}[/red]")
    return counts


def _edit(gate: Gate, item: ReviewItem, edit: Edit, console: Console) -> None:
    if item.hunt:
        new = edit(item.hunt.draft.query, ".kql")
        if new is None:
            console.print("[dim]No changes saved.[/dim]")
            return
        gate.edit_hunt(item, new)
    else:
        new = edit(json.dumps(item.stix, indent=2), ".json")
        if new is None:
            console.print("[dim]No changes saved.[/dim]")
            return
        gate.edit_stix(item, new)
    console.print("[green]Edit saved and logged. Review the new version:[/green]")


def render_item(item: ReviewItem, status: str, position: int, total: int) -> Panel:
    title = f"[{position}/{total}] {item.kind}: {item.label}"
    if status == "changed":
        title += "  (changed since its last decision)"
    body = _hunt_body(item) if item.hunt else _stix_body(item)
    return Panel(Group(*body), title=title, title_align="left")


def _hunt_body(item: ReviewItem) -> list:
    hunt, draft = item.hunt, item.hunt.draft
    lines = [
        Text(f"Kind: {hunt.kind}   Tables: {', '.join(draft.tables)}   "
             f"Confidence: {draft.confidence.score}/100 ({draft.confidence.rationale})"),
        *[Text(f'Evidence: "{q}"', style="cyan") for q in draft.evidence_quotes],
    ]  # fmt: skip
    if hunt.review:
        r = hunt.review
        lines.append(
            Text(f"First reviewer: faithful {r.faithful} · kql_correct {r.kql_correct}"
                 f" · actionable {r.actionable} · calibrated {r.calibrated}")
        )  # fmt: skip
        lines += [Text(f"  - {reason}", style="dim") for reason in r.reasons]
    else:
        lines.append(Text(f"Reviewer: {hunt.review_outcome}", style="dim"))
    if hunt.second_review:
        s = hunt.second_review
        lines.append(
            Text(f"Second reviewer ({hunt.second_review_model}): faithful {s.faithful} · "
                 f"kql_correct {s.kql_correct} · actionable {s.actionable} · "
                 f"calibrated {s.calibrated}")
        )  # fmt: skip
        lines += [Text(f"  - {reason}", style="dim") for reason in s.reasons]
    elif hunt.second_review_outcome:
        lines.append(Text(f"Second reviewer: {hunt.second_review_outcome}", style="dim"))
    lines += [
        Text(f"Lint {f.severity}: {f.code}: {f.message}",
             style="red" if f.severity == "error" else "yellow")
        for f in hunt.lint
    ]  # fmt: skip
    if hunt.needs_attention:
        lines.append(
            Text("Needs attention: " + "; ".join(hunt.attention_reasons), style="bold red")
        )
    if hunt.retire_when:
        lines.append(Text(hunt.retire_when, style="bold"))
    lines += [Text(""), Text(draft.query)]
    return lines


def indicator_table(items: list[ReviewItem]) -> Table:
    table = Table(title="Indicators that passed the validator and the re-check",
                  title_justify="left")  # fmt: skip
    for col in ("Value", "Pattern", "Evidence"):
        table.add_column(col, overflow="fold")
    for item in items:
        quote = item.stix.get("x_cti_agent_evidence_quote", "")
        table.add_row(item.stix.get("name", ""), item.stix.get("pattern", ""),
                      quote if len(quote) <= 90 else quote[:87] + "...")  # fmt: skip
    return table


def _stix_body(item: ReviewItem) -> list:
    obj = item.stix
    lines = []
    if "pattern" in obj:
        lines.append(Text(f"Pattern: {obj['pattern']}"))
    if obj.get("x_cti_agent_recheck_role"):
        lines.append(Text(f"Re-check: {obj['x_cti_agent_recheck_role'].replace('_', ' ')}"))
    if obj.get("aliases"):
        lines.append(Text(f"Aliases: {', '.join(obj['aliases'])}"))
    if obj.get("description"):
        lines.append(Text(f"Description: {obj['description']}"))
    if obj.get("x_cti_agent_evidence_quote"):
        page = obj.get("x_cti_agent_evidence_page")
        lines.append(
            Text(f'Evidence ({obj.get("x_cti_agent_evidence_kind")}'
                 f'{", page " + str(page) if page else ""}): '
                 f'"{obj["x_cti_agent_evidence_quote"]}"', style="cyan")
        )  # fmt: skip
    lines += [Text(f"Warning: {w}", style="yellow") for w in obj.get("x_cti_agent_warnings", [])]
    if obj.get("x_cti_agent_edited_by"):
        lines.append(Text(f"Edited by {obj['x_cti_agent_edited_by']}", style="dim"))
    return lines
