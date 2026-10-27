"""Save SVG captures of the terminal for the README, from the recorded AA23-320A run.

Nothing leaves the machine: the model's answers are replayed from tests/fixtures/llm, the run
goes to a temporary folder, and publish is a dry run. From the repo root:

    python scripts/demo_capture.py      # writes docs/media/*.svg

The CLI prints into a fake terminal in colour, and parts of that become SVGs through rich's own
export. Where a capture is cut short (the 42-row accepted table), the cut is marked in it.
"""

from __future__ import annotations

import io
import os
import re
import shlex
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.text import Text
from typer.testing import CliRunner

from cti_agent import cli
from cti_agent.audit import current_actor
from cti_agent.config import Settings
from cti_agent.review_ui import run_review
from cti_agent.stages.gate import Gate

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
MEDIA = ROOT / "docs" / "media"
WIDTH = 118

REPORT = "tests/fixtures/reports/aa23-320a.txt"
RECORDED = "tests/fixtures/llm/aa23-320a"
RECORDED_ANALYSIS = "tests/fixtures/llm/aa23-320a-analyse"

ENV = {
    "OUT_DIR": "out",
    "ATTACK_BUNDLE": str(FIXTURES / "attack-v20-subset-aa23-320a.json"),
    "ATTACK_MOBILE_BUNDLE": str(FIXTURES / "attack-mobile-v20-subset-aa23-320a.json"),
    "ALLOWLIST_FILE": str(ROOT / "data" / "allowlist.txt"),
    "RULES_FILE": str(ROOT / "data" / "my_rules.sample.csv"),
    "KQL_SCHEMA_FILE": str(ROOT / "data" / "kql_schema.json"),
    "CTI_AGENT_REVIEWER": "samuel",
}

# The scripted review: two hunts approved, the one the reviewer model flagged rejected, one
# approved, one skipped; then the actor and two attack-patterns approved, and stop.
REJECT_REASON = "Too broad: matches routine ETL and serverless admin work. Redraft narrower."
REVIEW_KEYS = ["a", "a", "r", "a", "s", "a", "a", "a", "q"]
FLAGGED = 3  # the review capture is the third item


class Terminal:
    """A fake terminal that the CLI prints into, with ANSI colour, at a fixed width."""

    def __init__(self) -> None:
        self.buffer = io.StringIO()
        self.console = Console(
            file=self.buffer, width=WIDTH, force_terminal=True, color_system="truecolor"
        )
        self.runner = CliRunner()
        cli.console = self.console

    def mark(self) -> int:
        return len(self.buffer.getvalue())

    def run(self, *args: str, exit_code: int = 0) -> None:
        self.console.print(Text("$ ", style="bold green") + Text("cti-agent " + shlex.join(args)))
        result = self.runner.invoke(cli.app, list(args))
        if result.exit_code != exit_code:
            raise SystemExit(
                f"cti-agent {shlex.join(args)} exited {result.exit_code}, expected {exit_code}:\n"
                f"{result.output}\n{result.exception!r}"
            )
        self.console.print()

    def note(self, text: str) -> None:
        self.console.print(Text(f"# {text}", style="dim italic"))

    def save(
        self,
        name: str,
        title: str,
        *spans: tuple[int, int | None],
        trim: Callable[[list[str]], list[str]] | None = None,
    ) -> None:
        text = "".join(self.buffer.getvalue()[start:end] for start, end in spans)
        lines = _tidy_paths(text).rstrip("\n").split("\n")
        if trim:
            lines = trim(lines)
        svg = Console(
            record=True, file=io.StringIO(), width=WIDTH, force_terminal=True,
            color_system="truecolor",
        )  # fmt: skip
        svg.print(Text.from_ansi("\n".join(lines)))  # wraps the few lines rich soft-wrapped
        svg.save_svg(str(MEDIA / f"{name}.svg"), title=title)
        print(f"wrote docs/media/{name}.svg ({len(lines)} lines)")


def _tidy_paths(text: str) -> str:
    """Windows prints out\\run\\brief.md; the README shows forward slashes."""
    return re.sub(r"\bout(?:\\[\w.\-]+)+", lambda m: m.group(0).replace("\\", "/"), text)


def shorten_table(title: str, keep: int) -> Callable[[list[str]], list[str]]:
    """Keep a table's first `keep` rows and mark how many were cut. A row that wraps takes
    several lines; its first line is the one with something in the first column."""

    def trim(lines: list[str]) -> list[str]:
        plain = [Text.from_ansi(line).plain for line in lines]
        top = next(i for i, p in enumerate(plain) if p.strip().startswith(title))
        first_row = top + 4  # title, top border, header, rule under the header
        bottom = next(i for i in range(first_row, len(plain)) if plain[i].lstrip().startswith("└"))
        starts = [i for i in range(first_row, bottom) if plain[i].split("│")[1].strip()]
        if len(starts) <= keep:
            return lines
        gap = f"\x1b[2;3m  ({len(starts) - keep} more rows, cut from this capture)\x1b[0m"
        return [*lines[: starts[keep]], lines[bottom], gap, *lines[bottom + 1 :]]

    return trim


def capture_review(term: Terminal, run_id: str) -> list[tuple[int, int]]:
    """Run the scripted review through the real review loop, echoing each key like a
    terminal would. Returns the spans to capture: the command, then the flagged item."""
    keys = iter(REVIEW_KEYS)
    marks: list[int] = []

    def ask(prompt: str, choices: list[str]) -> str:
        key = next(keys)
        assert key in choices, (key, choices)
        term.console.print(Text(f"{prompt}: ") + Text(key, style="bold"))
        marks.append(term.mark())
        return key

    def ask_text(prompt: str) -> str:
        term.console.print(Text(f"{prompt}: ") + Text(REJECT_REASON, style="bold"))
        marks[-1] = term.mark()
        return REJECT_REASON

    settings = Settings()
    gate = Gate(settings, run_id, current_actor(None), cli._audit_log(settings))
    command = term.mark()
    term.console.print(Text("$ ", style="bold green") + Text(f"cti-agent review {run_id}"))
    first_item = term.mark()
    run_review(gate, term.console, ask=ask, ask_text=ask_text, edit=lambda text, ext: None)
    return [(command, first_item), (marks[FLAGGED - 2], marks[FLAGGED - 1])]


def main() -> None:
    MEDIA.mkdir(parents=True, exist_ok=True)
    home = Path.cwd()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        for rel in (REPORT, RECORDED, RECORDED_ANALYSIS):
            source, target = ROOT / rel, Path(tmp) / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
        os.environ.update(ENV)
        os.chdir(tmp)  # relative paths in the output, and no .env picked up
        try:
            term = Terminal()

            start = term.mark()
            term.run("ingest", REPORT, "--tlp", "CLEAR", "--replay", RECORDED)
            accepted = shorten_table("Accepted (quote verified in source)", keep=6)
            term.save("ingest", "cti-agent ingest", (start, None), trim=accepted)
            [run_id] = [p.name for p in Path("out").iterdir() if p.is_dir()]

            start = term.mark()
            term.run("analyse", run_id, "--replay", RECORDED_ANALYSIS)
            term.save("analyse", "cti-agent analyse", (start, None))

            term.save("review", "cti-agent review", *capture_review(term, run_id))

            start = term.mark()
            term.run("audit", "--run", run_id, "--verify")
            term.save("audit", "cti-agent audit", (start, None))

            start = term.mark()
            term.run("publish", run_id, "--target", "sentinel")
            term.save("publish", "cti-agent publish (dry run)", (start, None))

            start = term.mark()
            log = Path("out") / "audit.jsonl"
            log.write_text(log.read_text("utf-8").replace('"approve"', '"reject"', 1), "utf-8")
            term.note("someone edits out/audit.jsonl by hand: an approval becomes a rejection")
            term.run("audit", "--verify", exit_code=4)
            term.run("review", run_id, exit_code=4)
            term.run("publish", run_id, exit_code=4)
            term.save(
                "tamper",
                "a tampered audit log",
                (start, None),
                trim=shorten_table("Audit log", keep=3),
            )
        finally:
            os.chdir(home)


if __name__ == "__main__":
    main()
