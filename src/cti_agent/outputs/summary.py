"""Short labels for a hunt, shared by the terminal and Slack."""

from __future__ import annotations

from cti_agent.models import Hunt


def review_scores(hunt: Hunt) -> str:
    """Faithful/KQL/actionable/calibrated from each reviewer, or why a review is missing."""

    def one(r, outcome):
        return f"{r.faithful}/{r.kql_correct}/{r.actionable}/{r.calibrated}" if r else outcome

    first = one(hunt.review, hunt.review_outcome)
    if hunt.second_review_outcome is None:
        return first
    return f"{first}, {one(hunt.second_review, hunt.second_review_outcome)}"


def lint_label(hunt: Hunt) -> str:
    errors = [f.code for f in hunt.lint if f.severity == "error"]
    warnings = [f.code for f in hunt.lint if f.severity == "warning"]
    if errors:
        return ", ".join(errors)
    return f"ok ({', '.join(warnings)})" if warnings else "ok"
