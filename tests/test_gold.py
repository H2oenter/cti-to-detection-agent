import json

import pytest
from conftest import FIXTURES
from pydantic import ValidationError

from cti_agent.evaluation.candidates import draft, stix_indicators, text_candidates
from cti_agent.evaluation.gold import GoldError, GoldReport, load_gold
from cti_agent.inputs import load_source
from cti_agent.stages.validator import normalise_value

AA23 = FIXTURES / "reports" / "aa23-320a.txt"


def gold(**overrides):
    base = {
        "report_id": "fx",
        "source": {"file": "reports/fx.txt", "sha256": "a" * 64},
        "labelled_by": "Samuel Omiwole",
        "labelled_on": "2026-11-01",
    }
    return GoldReport.model_validate({**base, **overrides})


def test_gold_values_are_normalised_like_the_validator():
    g = gold(
        indicators=[
            {"kind": "domain", "value": "Bad-Fixture[.]NET"},
            {"kind": "sha1", "value": "3F786850E387550FDAB836ED7E6DC881DE23001B"},
        ],
        techniques=["t1621"],
        cves=["cve-2024-55591"],
    )
    assert [i.value for i in g.indicators] == [
        "bad-fixture.net", "3f786850e387550fdab836ed7e6dc881de23001b"
    ]  # fmt: skip
    assert g.techniques == ["T1621"] and g.cves == ["CVE-2024-55591"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"labelled_by": " "}, "person's call"),
        ({"indicators": [{"kind": "ipv4", "value": "not-an-ip"}]}, "not a valid ipv4"),
        ({"techniques": ["TA0001"]}, "not technique IDs"),
        ({"techniques": ["T1621"], "optional_techniques": ["T1621"]}, "both required and optional"),
    ],
)
def test_bad_gold_files_are_refused(overrides, message):
    with pytest.raises(ValidationError, match=message):
        gold(**overrides)


def test_load_gold_skips_drafts_and_names_bad_files(tmp_path):
    good = gold().model_dump(mode="json")
    (tmp_path / "fx.json").write_text(json.dumps(good), encoding="utf-8")
    (tmp_path / "fx.draft.json").write_text("{}", encoding="utf-8")
    assert [g.report_id for g in load_gold(tmp_path)] == ["fx"]
    (tmp_path / "broken.json").write_text(json.dumps({**good, "labelled_by": ""}), "utf-8")
    with pytest.raises(GoldError, match=r"broken\.json"):
        load_gold(tmp_path)


def test_candidates_list_everything_in_the_text():
    indicators, techniques, cves = text_candidates(load_source(AA23))
    assert len(techniques) == 43 and "T1621" in techniques and "T1451" in techniques
    values = {v for _, v in indicators}
    # Traps a labeller must see and decide on: placeholders and the authors' contact address.
    assert {"targetsname-sso.com", "soc@mail.cisa.dhs.gov"} <= values
    assert "modus-operandi.html" not in values  # a split reference URL, not a domain
    assert cves == {}


def test_stix_cross_check_seeds_only_values_in_both(tmp_path):
    report = tmp_path / "fx.txt"
    report.write_text(
        "C2 at 198.51.101[.]7 and update-portal-fixture[.]net.\n"
        "Loader SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "Actors used T1219.",
        encoding="utf-8",
    )
    stix = tmp_path / "fx-stix.json"
    digest = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    objects = [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.101.7']"},
        {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{digest}']"},
        {"type": "domain-name", "value": "only-in-stix-fixture.net"},
    ]
    stix.write_text(json.dumps({"type": "bundle", "objects": objects}), encoding="utf-8")
    assert ("domain", "only-in-stix-fixture.net") in stix_indicators(stix)

    result = draft(load_source(report), "fx", stix)
    seeded = {(i["kind"], i["value"]) for i in result["gold"]["indicators"]}
    assert seeded == {
        ("ipv4", "198.51.101.7"),
        ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    }
    buckets = result["indicator_candidates"]
    assert [c["value"] for c in buckets["text_only"]] == ["update-portal-fixture.net"]
    assert [c["value"] for c in buckets["stix_only"]] == ["only-in-stix-fixture.net"]
    assert result["gold"]["techniques"] == ["T1219"] and result["gold"]["labelled_by"] == ""


def test_html_file_names_are_not_domains():
    assert normalise_value("domain", "modus-operandi.html") is None
