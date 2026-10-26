"""Deterministic checks on model-drafted KQL. No LLM, no network, nothing is executed.

KQL looks read-only, but some operators reach out of the workspace: `externaldata`
reads URLs, `http_request` makes outbound calls, plugins run code, and cross-scope
functions read other workspaces. A poisoned report could steer a draft towards
them, so they are errors here, before any human is asked to run the query.

Table and column checks use data/kql_schema.json, built from Microsoft's docs.
Column checks are best effort and only ever warn.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from cti_agent.models import LintFinding

FORBIDDEN: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bexternaldata\b|\bexternal_table\s*\(", re.I), "external_data",
     "reads data from outside the workspace (externaldata / external_table)"),
    (re.compile(r"\bhttp_request(?:_post)?\b", re.I), "http_request",
     "makes outbound HTTP calls (http_request plugin)"),
    (re.compile(r"\bevaluate\s+(?:python|r|sql_request|cosmosdb_sql_request|mysql_request|"
                r"postgresql_request|azure_digital_twins_query_request|ai_\w+)\s*\(", re.I),
     "code_plugin", "runs code or queries another service (evaluate plugin)"),
    (re.compile(r"(?m)^\s*\.[A-Za-z]"), "management_command",
     "contains a management command (line starting with '.')"),
    (re.compile(r"\b(?:workspace|app|cluster|database|adx)\s*\(", re.I), "cross_scope",
     "reads another workspace, app, cluster or database"),
]  # fmt: skip
TIME_FILTER = re.compile(
    r"\bago\s*\(|\bbetween\s*\(|\bstartof(?:day|week|month|year)\s*\(|\bdatetime\s*\(", re.I
)
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\S")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class KqlSchema:
    tables: dict[str, frozenset[str]]

    @classmethod
    def load(cls, path: Path) -> KqlSchema:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls({name: frozenset(t["columns"]) for name, t in data["tables"].items()})


def strip_literals(query: str) -> str:
    """Replace string literals with "" and drop // comments, so checks only see code."""
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        if query.startswith("//", i):
            end = query.find("\n", i)
            i = n if end < 0 else end
            continue
        if query.startswith("```", i):
            end = query.find("```", i + 3)
            i = n if end < 0 else end + 3
            out.append('""')
            continue
        char = query[i]
        prefixed = (
            char in "@hH" and i + 1 < n and query[i + 1] in "\"'"
            and (i == 0 or not (query[i - 1].isalnum() or query[i - 1] == "_"))
        )  # fmt: skip
        if char in "\"'" or prefixed:
            start = i + 1 if prefixed else i
            quote = query[start]
            j = start + 1
            while j < n and query[j] != quote:
                j += 2 if (query[j] == "\\" and char != "@") else 1
            i = j + 1
            out.append('""')
            continue
        out.append(char)
        i += 1
    return "".join(out)


def lint_kql(query: str, declared_tables: list[str], schema: KqlSchema) -> list[LintFinding]:
    findings: list[LintFinding] = []
    if not query.strip():
        return [LintFinding(severity="error", code="empty_query", message="the query is empty")]
    code = strip_literals(query)

    for pattern, code_name, message in FORBIDDEN:
        if pattern.search(code):
            findings.append(LintFinding(severity="error", code=code_name, message=message))

    let_names = set(re.findall(r"\blet\s+([A-Za-z_]\w*)\s*=", code))
    used: set[str] = set()
    for source in _sources(code):
        if source in schema.tables:
            used.add(source)
        elif source in let_names:
            continue
        elif source[0].isupper():
            findings.append(
                LintFinding(
                    severity="error",
                    code="unknown_table",
                    message=f"{source} is not a known Sentinel or Defender table",
                )
            )
        else:
            findings.append(
                LintFinding(
                    severity="warning",
                    code="unverified_source",
                    message=f"{source} can't be checked (function or parser?)",
                )
            )
    for table in schema.tables:  # tables referenced in other positions, e.g. inside join
        if table not in used and re.search(rf"\b{table}\b", code):
            used.add(table)

    if used:
        unknown = _unknown_columns(code, used, schema, let_names)
        if unknown:
            findings.append(
                LintFinding(
                    severity="warning",
                    code="unknown_columns",
                    message="not columns of " + ", ".join(sorted(used)) + ": "
                    + ", ".join(sorted(unknown)),
                )
            )  # fmt: skip
    if not TIME_FILTER.search(code):
        findings.append(
            LintFinding(
                severity="warning",
                code="no_time_filter",
                message="no time bound (ago(), between() or datetime())",
            )
        )
    declared = {t.strip() for t in declared_tables if t.strip()}
    if declared != used:
        findings.append(
            LintFinding(
                severity="warning",
                code="tables_mismatch",
                message=f"declared {sorted(declared)} but the query reads {sorted(used)}",
            )
        )
    return findings


def _sources(code: str) -> list[str]:
    """Identifiers in positions where KQL expects a table: query starts, subqueries, unions."""
    tokens = _TOKEN.findall(code)
    sources: list[str] = []
    in_union = False
    for i, tok in enumerate(tokens):
        prev = tokens[i - 1] if i else None
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok == "union":
            in_union = True
            continue
        if tok in ("|", ";", ")"):
            in_union = False
        if not _IDENT.match(tok) or nxt in ("(", "=", ":", "."):
            continue
        if prev == "=" and i >= 2 and _IDENT.match(tokens[i - 2]) and not _is_let(tokens, i - 2):
            continue  # named argument such as kind=inner
        starts = (
            prev is None
            or prev == ";"
            or (prev == "=" and _is_let(tokens, i - 2))
            or (prev == "(" and _opens_subquery(tokens, i - 1))
            or (in_union and prev in ("union", ","))
            or (prev in ("join", "lookup"))
        )
        if starts and tok not in _KEYWORDS:
            sources.append(tok)
    return sources


def _is_let(tokens: list[str], name_index: int) -> bool:
    return name_index >= 1 and tokens[name_index - 1] == "let"


def _opens_subquery(tokens: list[str], paren_index: int) -> bool:
    before = tokens[paren_index - 1] if paren_index else None
    return before is None or not _IDENT.match(before) or before in ("in", "join", "lookup")


_KEYWORDS = {
    "let", "union", "join", "lookup", "kind", "where", "project", "extend", "summarize", "by",
    "print", "range", "datatable", "materialize", "toscalar", "on", "as", "with", "in", "and",
    "or", "not", "true", "false", "set", "declare", "pattern", "restrict", "evaluate",
}  # fmt: skip


def _unknown_columns(code: str, used: set[str], schema: KqlSchema, let_names: set[str]) -> set[str]:
    known = set().union(*(schema.tables[t] for t in used)) | used | let_names
    assigned = set(re.findall(r"\b([A-Za-z_]\w*)\s*=(?!=)", code))
    assigned |= set(re.findall(r"\bas\s+([A-Za-z_]\w*)", code))
    unknown = set()
    for match in re.finditer(r"(?<![.\w])([A-Z][A-Za-z0-9_]*)\b(?!\s*[(:])", code):
        name = match.group(1)
        if name not in known and name not in assigned:
            unknown.add(name)
    return unknown
