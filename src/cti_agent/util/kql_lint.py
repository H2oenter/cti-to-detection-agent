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
    return scan_literals(query)[0]


# After a string closes, KQL expects a space, an operator or punctuation. A letter, digit, "?",
# a backslash or "@" means the string ended earlier than its author thought.
_RUNS_ON = re.compile(r"[A-Za-z0-9_?\\@]")


def scan_literals(query: str) -> tuple[str, list[LintFinding]]:
    """Read string literals the way KQL does, so the checks see the same code KQL would run.

    "..." and '...' take backslash escapes. @"..." is verbatim: a backslash is just a
    character, and a quote inside is written twice (""). An h or H in front hides the value
    in logs and doesn't change the rules. None of these can span lines; ``` ... ``` can.
    Returns the query with each literal replaced by "" and // comments dropped, plus an
    error for each literal KQL couldn't parse. A literal the lint reads differently from KQL
    could hide code from the checks, so these are errors, not warnings.
    """
    out: list[str] = []
    findings: list[LintFinding] = []
    i, n = 0, len(query)
    while i < n:
        if query.startswith("//", i):
            end = query.find("\n", i)
            i = n if end < 0 else end
            continue
        if query.startswith("```", i):
            end = query.find("```", i + 3)
            if end < 0:
                findings.append(_unterminated(query[i : i + 40]))
            i = n if end < 0 else end + 3
            out.append('""')
            continue
        found = _literal_at(query, i)
        if found is None:
            out.append(query[i])
            i += 1
            continue
        start, verbatim = found
        quote, k, closed = query[start], start + 1, False
        while k < n and query[k] not in "\r\n":
            if query[k] == quote:
                if verbatim and query.startswith(quote * 2, k):
                    k += 2  # a doubled quote inside @"...": one quote character
                    continue
                closed = True
                break
            k += 2 if (query[k] == "\\" and not verbatim) else 1
        out.append('""')
        line_start = max(query.rfind("\n", 0, i), query.rfind("\r", 0, i)) + 1
        if not closed:
            findings.append(_unterminated(query[max(i - 24, line_start) : k]))
            i = k  # carry on from the line break
            continue
        i = k + 1
        if i < n and _RUNS_ON.match(query[i]):
            line_end = min((e for e in (query.find("\n", i), query.find("\r", i)) if e >= 0),
                           default=n)  # fmt: skip
            hint = (
                '; inside @"..." a backslash doesn\'t escape a quote, so the string ends there: '
                'write a quote inside it as ""'
                if verbatim and query[k - 1] == "\\"
                else ""
            )
            findings.append(
                LintFinding(
                    severity="error",
                    code="broken_string",
                    message=f"text runs straight on after a string closes: "
                    f"{_snippet(query[max(i - 24, line_start) : min(i + 8, line_end)])}{hint}",
                )
            )
    return "".join(out), findings


def _literal_at(query: str, i: int) -> tuple[int, bool] | None:
    """If a string literal starts at i, (index of its opening quote, verbatim)."""
    if query[i] in "\"'":
        return i, False
    if i > 0 and (query[i - 1].isalnum() or query[i - 1] == "_"):
        return None  # the h in "with" doesn't start a string
    j = i + 1 if query[i] in "hH" else i
    verbatim = query.startswith("@", j)
    j += 1 if verbatim else 0
    if j < len(query) and query[j] in "\"'" and j > i:
        return j, verbatim
    return None


def _unterminated(text: str) -> LintFinding:
    return LintFinding(
        severity="error",
        code="unterminated_string",
        message=f"a string isn't closed before the end of its line: {_snippet(text)}; KQL "
        "strings can't span lines (``` ... ``` can)",
    )


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= 40 else text[:37] + "..."


def lint_kql(query: str, declared_tables: list[str], schema: KqlSchema) -> list[LintFinding]:
    if not query.strip():
        return [LintFinding(severity="error", code="empty_query", message="the query is empty")]
    code, findings = scan_literals(query)

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
            or (prev == "(" and _opens_subquery(tokens, i - 1, nxt))
            or (in_union and prev in ("union", ","))
            or (prev in ("join", "lookup"))
        )
        if starts and tok not in _KEYWORDS:
            sources.append(tok)
    return sources


def _is_let(tokens: list[str], name_index: int) -> bool:
    return name_index >= 1 and tokens[name_index - 1] == "let"


def _opens_subquery(tokens: list[str], paren_index: int, nxt: str | None) -> bool:
    """Does this "(" hold a subquery, as in "in (T | ...)" or "join kind=inner (T | ...)"?"""
    j = paren_index - 1
    while j >= 2 and tokens[j - 1] == "=":  # skip parameters such as kind=inner
        j -= 3
    before = tokens[j] if j >= 0 else None
    if before in ("in", "join", "lookup"):
        return True
    # A bare parenthesis is a subquery only when a pipe follows the name: "(T | where ...)".
    # Without that, "(RegTime - 1h)" would read as a table called RegTime.
    return (before is None or not _IDENT.match(before)) and nxt == "|"


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
