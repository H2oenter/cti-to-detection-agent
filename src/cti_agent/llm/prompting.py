"""Versioned prompts. Each file in llm/prompts/ starts with a `version:` front-matter line."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PROMPT_DIR = Path(__file__).parent / "prompts"


@dataclass(frozen=True)
class Prompt:
    name: str
    version: str
    text: str


def load_prompt(name: str) -> Prompt:
    raw = (PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8")
    _, front, body = raw.split("---", 2)
    meta = dict(line.split(":", 1) for line in front.strip().splitlines() if ":" in line)
    return Prompt(name=name, version=meta["version"].strip(), text=body.strip())
