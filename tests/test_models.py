import pytest
from pydantic import ValidationError

from cti_agent.models import Confidence, Extraction, VulnAdvisory


def test_extraction_schema_requires_evidence_on_every_item():
    defs = Extraction.model_json_schema()["$defs"]
    for name in ("ExtractedIndicator", "ExtractedTechnique", "ExtractedActor", "ExtractedCVE"):
        assert "evidence" in defs[name]["required"], name
    assert defs["Evidence"]["required"] == ["quote"]


def test_indicator_kind_is_closed():
    with pytest.raises(ValidationError):
        Extraction.model_validate(
            {
                "report_title": "t",
                "actors": [],
                "cves": [],
                "techniques": [],
                "indicators": [
                    {"kind": "mutex", "value": "x", "context": "c", "evidence": {"quote": "x"}}
                ],
            }
        )


@pytest.mark.parametrize("score", [-1, 101])
def test_confidence_bounds(score):
    with pytest.raises(ValidationError):
        Confidence(score=score, rationale="r")


def test_vuln_advisory_minimal_and_bounds():
    adv = VulnAdvisory(id="CVE-2024-4577", source="cve", description="PHP-CGI argument injection")
    assert adv.references == [] and adv.kev_listed is False
    with pytest.raises(ValidationError):
        VulnAdvisory(id="x", source="cve", description="d", cvss_score=11)
