"""`cti-agent eval`: run the pipeline on every gold report and score it.

Each eval writes its runs under out/eval/<timestamp>/ (with its own database), so eval
runs never mix with real ones. Results go to eval/results/<date>.json and .md.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cti_agent.attack.attack_index import AttackLookup
from cti_agent.config import Settings
from cti_agent.evaluation.gold import GoldReport, load_gold
from cti_agent.evaluation.score import PRF, ReportScore, score_report
from cti_agent.llm.client import LLMClient
from cti_agent.llm.prompting import load_prompt
from cti_agent.pipeline import run_ingest
from cti_agent.trace import read_trace
from cti_agent.util.normalise import sha256_file


class EvalError(Exception):
    pass


@dataclass
class GoldEval:
    run_at: datetime
    model: str
    prompt_version: str
    scores: list[ReportScore]
    out_dir: Path
    replayed: bool = False
    notes: list[str] = field(default_factory=list)

    def overall(self) -> dict[str, PRF]:
        total = {name: PRF() for name in ("indicators", "techniques", "raw_indicators",
                                          "raw_techniques")}  # fmt: skip
        for s in self.scores:
            for name in total:
                total[name] = total[name] + getattr(s, name)
        return total

    def as_dict(self) -> dict:
        return {
            "run_at": self.run_at.isoformat(timespec="seconds"),
            "model": self.model,
            "prompt_version": self.prompt_version,
            "replayed": self.replayed,
            "reports": [s.as_dict() for s in self.scores],
            "overall": {k: v.as_dict() for k, v in self.overall().items()},
            "notes": self.notes,
        }


def pinned_source(gold: GoldReport) -> Path:
    """The report file the labels were made on, refused if it has changed since."""
    path = Path(gold.source.file)
    if not path.exists():
        raise EvalError(f"{gold.report_id}: {path} is missing; put the report there first")
    if sha256_file(path) != gold.source.sha256:
        raise EvalError(
            f"{gold.report_id}: {path} isn't the version that was labelled (SHA-256 differs); "
            "check the labels against the new version and update source.sha256"
        )
    return path


def run_gold_eval(
    settings: Settings,
    client: LLMClient,
    gold_dir: Path,
    *,
    attack: AttackLookup | None = None,
    source_for: Callable[[GoldReport], Path] = pinned_source,
    now: datetime | None = None,
    replayed: bool = False,
) -> GoldEval:
    golds = load_gold(gold_dir)
    if not golds:
        raise EvalError(f"no gold files in {gold_dir}; see eval/gold/README.md")
    sources = {g.report_id: source_for(g) for g in golds}  # check every file before any spend
    now = now or datetime.now(UTC)
    out_dir = settings.out_dir / "eval" / f"{now:%Y%m%dT%H%M%SZ}"
    eval_settings = settings.model_copy(update={"out_dir": out_dir})
    scores = []
    for gold in golds:
        result = run_ingest(sources[gold.report_id], "CLEAR", eval_settings, client, attack=attack)
        score = score_report(gold, result.run_id, result.validation, result.chunks)
        trace = read_trace(result.out_dir / "trace.jsonl")
        score.input_tokens = sum(r["input_tokens"] for r in trace)
        score.output_tokens = sum(r["output_tokens"] for r in trace)
        score.cost_usd = round(sum(r["est_cost_usd"] for r in trace), 6)
        scores.append(score)
    return GoldEval(
        run_at=now,
        model=settings.extract_model,
        prompt_version=load_prompt("collector").version,
        scores=scores,
        out_dir=out_dir,
        replayed=replayed,
    )


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def gold_markdown(result: GoldEval) -> str:
    lines = [
        f"Run {result.run_at:%Y-%m-%d} · extraction model `{result.model}` "
        f"(`{result.prompt_version}`){' · replayed' if result.replayed else ''}",
        "",
        "| Report | Indicators P / R / F1 | Techniques P / R / F1 | Raw → validated precision "
        "(indicators) | Evidence pass rate | Rejected | Cost |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    rows = [(s.report_id, s.indicators, s.techniques, s.raw_indicators, s.evidence_pass_rate,
             sum(s.rejections.values()), s.cost_usd) for s in result.scores]  # fmt: skip
    total = result.overall()
    checked = sum(s.items_checked for s in result.scores)
    passed = sum((s.evidence_pass_rate or 0) * s.items_checked for s in result.scores)
    rows.append(("**overall**", total["indicators"], total["techniques"], total["raw_indicators"],
                 passed / checked if checked else None,
                 sum(sum(s.rejections.values()) for s in result.scores),
                 sum(s.cost_usd for s in result.scores)))  # fmt: skip
    for report, ind, tech, raw, evidence, rejected, cost in rows:
        lines.append(
            f"| {report} | {_pct(ind.precision)} / {_pct(ind.recall)} / {_pct(ind.f1)} "
            f"| {_pct(tech.precision)} / {_pct(tech.recall)} / {_pct(tech.f1)} "
            f"| {_pct(raw.precision)} → {_pct(ind.precision)} | {_pct(evidence)} "
            f"| {rejected} | ${cost:.3f} |"
        )
    return "\n".join(lines) + "\n"


def write_results(result: GoldEval, results_dir: Path, injection: dict | None = None) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    stem = results_dir / f"{result.run_at:%Y-%m-%d}"
    data = {"gold": result.as_dict(), "injection": injection}
    stem.with_suffix(".json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    markdown = gold_markdown(result)
    if injection:
        markdown += "\n" + injection["markdown"]
    stem.with_suffix(".md").write_text(markdown, encoding="utf-8")
    return stem.with_suffix(".md")
