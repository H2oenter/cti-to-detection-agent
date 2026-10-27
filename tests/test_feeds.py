"""Feed fetching, mapping and triage, against recorded real feed samples. No network."""

import json
import urllib.error
from datetime import UTC, datetime, timedelta

import pytest
from conftest import FIXTURES, ROOT, FakeOpener

from cti_agent.feeds.fetch import (
    find_advisory,
    parse_since,
    probe_templates,
    run_fetch,
    top_candidates,
)
from cti_agent.feeds.http import FeedError, Fetcher, _AllowlistRedirects, build_url, load_sources
from cti_agent.feeds.sources import (
    cve_record_url,
    fetch_osv,
    map_cve,
    map_kev,
    map_osv,
    recent_cve_ids,
    recent_osv_ids,
)
from cti_agent.feeds.triage import load_watchlist, ranked, tier_for, triage
from cti_agent.models import VulnAdvisory

FEEDS = FIXTURES / "feeds"
SOURCES = load_sources(ROOT / "data" / "sources.toml")
WATCHLIST = load_watchlist(ROOT / "data" / "watchlist.toml")
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
CVE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def read(name):
    return (FEEDS / name).read_bytes()


def record(name):
    return json.loads(read(name))


def fetcher(routes):
    opener = FakeOpener(routes)
    return Fetcher.from_sources(SOURCES, opener=opener), opener


# --- the network boundary ---------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/collect",
        "http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://raw.githubusercontent.com.evil.example/x",
    ],
)
def test_fetcher_refuses_anything_off_the_allowlist(url):
    f, opener = fetcher({url: b"x"})
    with pytest.raises(FeedError, match="allowlist"):
        f.get(url)
    assert opener.urls == []


def test_redirects_off_the_allowlist_are_refused():
    handler = _AllowlistRedirects(frozenset(["www.cisa.gov"]))
    with pytest.raises(FeedError, match="redirect"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/x")


@pytest.mark.parametrize("bad", ["../../etc/passwd", "CVE-2024-4577/../x", "GHSA-x?y=1"])
def test_ids_are_checked_before_they_reach_a_url(bad):
    with pytest.raises(FeedError):
        build_url(SOURCES["osv"]["record"], SOURCES["osv"]["id_pattern"],
                  ecosystem="npm", id=bad)  # fmt: skip


def test_cve_record_url_is_built_from_the_id():
    assert cve_record_url(SOURCES["cvelist"], "CVE-2024-4577") == (
        f"{CVE_BASE}/2024/4xxx/CVE-2024-4577.json"
    )
    assert cve_record_url(SOURCES["cvelist"], "CVE-2026-109618").endswith(
        "/2026/109xxx/CVE-2026-109618.json"
    )


def test_oversized_responses_are_refused():
    f, _ = fetcher({"https://www.cisa.gov/big": b"x" * 50})
    f.max_bytes = 10
    with pytest.raises(FeedError, match="larger"):
        f.get("https://www.cisa.gov/big")


# --- mapping ----------------------------------------------------------------------------


def test_map_cve_php_cgi():
    adv = map_cve(record("CVE-2024-4577.json"))
    [php] = adv.affected
    assert (php.vendor, php.product, php.platforms, php.modules) == (
        "PHP Group", "PHP", ["Windows"], ["CGI"]
    )  # fmt: skip
    assert ("8.1.0", "8.1.29") in [(r.introduced, r.fixed) for r in php.ranges]
    assert adv.cwes == ["CWE-78"] and adv.cvss_score == 9.8
    assert adv.ssvc_exploitation == "active" and adv.kev_listed and adv.patch_available
    assert "Best-Fit" in adv.description


def test_map_cve_wildcard_bounds_are_not_fixed_versions():
    adv = map_cve(record("CVE-2024-27980.json"))
    ranges = [r for p in adv.affected for r in p.ranges]
    assert all("*" not in (r.fixed or "") for r in ranges)
    assert any(r.last_affected == "4.*" for r in ranges)


def test_map_kev_and_osv():
    kev = map_kev(record("kev.json")["vulnerabilities"][0])
    assert kev.kev_listed and kev.source == "kev" and kev.affected[0].vendor == "PHP Group"
    osv = map_osv(record("osv-GHSA-84wq-86v6-x5j6.json"))
    assert osv.affected[0].ecosystem == "Packagist" and osv.cwes == ["CWE-400", "CWE-770"]
    assert osv.patch_available and "CVE-" in osv.aliases[0]


# --- reading the indexes ----------------------------------------------------------------


def test_osv_index_stops_at_the_window_and_skips_malicious_packages():
    url = f"{OSV_BASE}/npm/modified_id.csv"
    f, _ = fetcher({url: read("osv-npm-modified_id.csv")})
    ids, malicious = recent_osv_ids(f, SOURCES["osv"], "npm", datetime(2026, 10, 1, tzinfo=UTC))
    assert ids == [] and malicious == 4

    url = f"{OSV_BASE}/Packagist/modified_id.csv"
    f, _ = fetcher({url: read("osv-Packagist-modified_id.csv")})
    since = datetime(2026, 10, 26, 15, 0, 5, 320000, tzinfo=UTC)
    ids, _ = recent_osv_ids(f, SOURCES["osv"], "Packagist", since)
    assert ids == ["GHSA-84wq-86v6-x5j6", "GHSA-38p6-h87p-r4cg"]


def test_one_failing_ecosystem_is_logged_and_the_rest_still_load():
    since = datetime(2026, 10, 26, 15, 0, 5, 320000, tzinfo=UTC)
    f, _ = fetcher({
        f"{OSV_BASE}/Packagist/modified_id.csv": read("osv-Packagist-modified_id.csv"),
        f"{OSV_BASE}/Packagist/GHSA-84wq-86v6-x5j6.json": read("osv-GHSA-84wq-86v6-x5j6.json"),
        f"{OSV_BASE}/Packagist/GHSA-38p6-h87p-r4cg.json": read("osv-GHSA-38p6-h87p-r4cg.json"),
    })  # fmt: skip
    errors = []
    cfg = {**SOURCES["osv"], "ecosystems": ["PyPI", "Packagist"]}
    items, _ = fetch_osv(f, cfg, since, errors)
    assert len(items) == 2 and len(errors) == 1 and errors[0].startswith("osv PyPI:")


@pytest.mark.parametrize("osv_id", ["GO-2026-4321", "RUSTSEC-2026-0012", "PYSEC-2026-77"])
def test_newer_ecosystem_ids_are_accepted(osv_id):
    url = build_url(SOURCES["osv"]["record"], SOURCES["osv"]["id_pattern"],
                    ecosystem="crates.io", id=osv_id)  # fmt: skip
    assert url.endswith(f"/crates.io/{osv_id}.json")


def test_delta_log_head_is_read_until_the_window_ends():
    log = read("deltaLog-head.json")
    url = SOURCES["cvelist"]["delta_log"]
    f, _ = fetcher({url: log})
    entries = json.loads(log)
    every = recent_cve_ids(f, SOURCES["cvelist"], datetime(2026, 10, 1, tzinfo=UTC))
    assert every and every[0] == (entries[0].get("new") + entries[0].get("updated"))[0]["cveId"]
    later = datetime.fromisoformat(entries[0]["fetchTime"].replace("Z", "+00:00"))
    assert recent_cve_ids(f, SOURCES["cvelist"], later + timedelta(seconds=1)) == []
    # A ranged read that cuts an entry in half still yields the complete ones.
    f, _ = fetcher({url: log[:-60]})  # cuts the last entry only
    assert recent_cve_ids(f, SOURCES["cvelist"], datetime(2026, 10, 1, tzinfo=UTC))


# --- triage -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "tier", "product"),
    [
        ("CVE-2024-4577.json", "hunt now", "PHP"),  # KEV, SSVC active, OS command injection
        ("CVE-2026-109618.json", "hunt soon", "PHP"),  # CVSS 9.2 RCE, no exploitation yet
        ("CVE-2024-27980.json", "watch", "Node.js"),  # RCE, but CVSS 8.1 and not exploited
        ("osv-GHSA-84wq-86v6-x5j6.json", "watch", "PHP"),  # a Composer package; a HIGH DoS
    ],
)
def test_triage_tiers(name, tier, product):
    adv = map_cve(record(name)) if name.startswith("CVE") else map_osv(record(name))
    result = triage(adv, WATCHLIST)
    assert result.tier == tier and result.passed is (tier in ("hunt now", "hunt soon"))
    assert result.product.name == product


def test_any_product_is_hunted_once_exploited():
    """The Arista KEV entry used to fail triage for not being on the watchlist."""
    arista = map_kev(record("kev.json")["vulnerabilities"][2])
    result = triage(arista, WATCHLIST)
    assert result.tier == "hunt now" and result.product is None
    assert (result.exploited, result.impact) == (["CISA KEV"], ["SQL injection"])


@pytest.mark.parametrize(
    ("exploited", "impact", "cvss", "tier"),
    [
        (["CISA KEV"], [], None, "hunt now"),  # a bare KEV entry: no score, still hunted
        (["CISA KEV"], [], 5.3, "watch"),  # exploited, but known to be minor
        ([], ["auth bypass"], 9.1, "hunt soon"),
        ([], ["auth bypass"], 8.8, "watch"),
        ([], [], 9.8, "watch"),  # critical, but no impact class to hunt for
        ([], [], 4.0, "other"),
    ],
)
def test_tier_rules(exploited, impact, cvss, tier):
    assert tier_for(exploited, impact, cvss) == tier


def advisory(**fields):
    base = {"id": "CVE-2026-0001", "source": "cve", "description": "A flaw in Fixture Gateway."}
    return VulnAdvisory.model_validate({**base, **fields})


@pytest.mark.parametrize(
    ("text", "exploited"),
    [
        ("Fixture Corp is aware of reports that this vulnerability has been exploited.", True),
        ("This zero-day was used in limited, targeted attacks.", True),
        ("An attacker could exploit this to run code.", False),
        ("Reported via the Trend Micro Zero Day Initiative. Was ZDI-CAN-1234.", False),
    ],
)
def test_vendor_wording_counts_as_exploited(text, exploited):
    assert bool(triage(advisory(description=text), []).exploited) is exploited


def test_negated_wording_is_not_exploitation():
    text = "There is no evidence that this vulnerability has been exploited. It is a zero-day."
    result = triage(advisory(description=text), [])
    assert result.exploited == ['wording: "zero-day"']  # the second sentence still counts
    calm = triage(advisory(description="We are not aware of any exploitation in the wild."), [])
    assert calm.exploited == []


def test_a_severity_label_stands_in_for_a_missing_score():
    critical = advisory(source="osv", severity="critical", cwes=["CWE-502"])
    assert triage(critical, []).tier == "hunt soon"
    assert triage(advisory(source="osv", severity="low", cwes=["CWE-502"]), []).tier == "watch"


def test_the_prompt_signal_list_is_unchanged():
    """The pre-patch analyst prompt quotes this list; recorded runs are keyed on prompt text."""
    php = triage(map_cve(record("CVE-2024-4577.json")), WATCHLIST)
    node = triage(map_cve(record("CVE-2024-27980.json")), WATCHLIST)
    assert php.signals == ["CWE-78", "CISA KEV", "SSVC exploitation: active"]
    assert node.signals == ["CWE-77"]


def test_no_fix_listed_and_zero_day():
    unfixed = {"vendor": "Fixture", "product": "Gateway",
               "ranges": [{"introduced": "1.0", "last_affected": "2.4"}]}  # fmt: skip
    exploited = triage(advisory(affected=[unfixed], kev_listed=True, cwes=["CWE-787"]), [])
    assert exploited.no_fix and exploited.zero_day and exploited.tier == "hunt now"
    assert "memory corruption" in exploited.impact and "no fix listed" in exploited.reasons
    fixed = {**unfixed, "ranges": [{"introduced": "1.0", "fixed": "2.5"}]}
    assert not triage(advisory(affected=[fixed], kev_listed=True), []).zero_day
    assert not triage(advisory(kev_listed=True), []).no_fix  # no version data: unknown
    worded = advisory(description="No patch is available yet; apply the mitigation.")
    assert triage(worded, []).no_fix


def test_watchlist_ranks_first_within_a_tier():
    php = map_cve(record("CVE-2024-4577.json"))
    other = advisory(kev_listed=True, cwes=["CWE-78"], cvss_score=10.0)
    ranked_ids = [t.advisory.id for t in ranked([triage(other, WATCHLIST),
                                                 triage(php, WATCHLIST)])]  # fmt: skip
    assert ranked_ids == ["CVE-2024-4577", "CVE-2026-0001"]  # PHP first despite 9.8 < 10.0


# --- the exploit-template probe ---------------------------------------------------------

NUCLEI = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"


def test_exists_is_false_only_on_404():
    f, _ = fetcher({"https://www.cisa.gov/here": b"x"})
    assert f.exists("https://www.cisa.gov/here") is True
    assert f.exists("https://www.cisa.gov/missing") is False

    class Broken:
        def open(self, request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 500, "boom", {}, None)

    with pytest.raises(FeedError, match="500"):
        Fetcher.from_sources(SOURCES, opener=Broken()).exists("https://www.cisa.gov/here")


def test_template_probe_checks_only_where_it_can_change_the_tier():
    soon = triage(advisory(id="CVE-2026-0002", cwes=["CWE-306"], cvss_score=9.8), [])
    watch = triage(advisory(id="CVE-2026-0003", cwes=["CWE-22"], cvss_score=7.5), [])
    now = triage(advisory(id="CVE-2026-0004", kev_listed=True), [])
    f, opener = fetcher({f"{NUCLEI}/network/cves/2026/CVE-2026-0003.yaml": b"id: x"})
    errors = []
    found = probe_templates(f, SOURCES["nuclei"], [now, watch, soon], errors)
    assert found == {"CVE-2026-0003": ("public Nuclei template",)} and errors == []
    assert not any("CVE-2026-0004" in url for url in opener.urls)  # already exploited
    promoted = triage(watch.advisory, [], found["CVE-2026-0003"])
    assert promoted.tier == "hunt now"


# --- fetch end to end -------------------------------------------------------------------


def test_run_fetch_files_triages_and_never_follows_links(settings, tmp_path):
    settings = settings.model_copy(
        update={
            "inbox_dir": tmp_path / "inbox",
            "sources_file": ROOT / "data" / "sources.toml",
            "watchlist_file": ROOT / "data" / "watchlist.toml",
        }
    )
    routes = {
        SOURCES["kev"]["catalogue"]: read("kev.json"),
        f"{OSV_BASE}/npm/modified_id.csv": read("osv-npm-modified_id.csv"),
        f"{OSV_BASE}/Packagist/modified_id.csv": read("osv-Packagist-modified_id.csv"),
        f"{OSV_BASE}/Packagist/GHSA-84wq-86v6-x5j6.json": read("osv-GHSA-84wq-86v6-x5j6.json"),
        f"{OSV_BASE}/Packagist/GHSA-38p6-h87p-r4cg.json": read("osv-GHSA-38p6-h87p-r4cg.json"),
        f"{CVE_BASE}/2024/4xxx/CVE-2024-4577.json": read("CVE-2024-4577.json"),
        f"{CVE_BASE}/2024/27xxx/CVE-2024-27980.json": read("CVE-2024-27980.json"),
        f"{CVE_BASE}/2026/109xxx/CVE-2026-109618.json": read("CVE-2026-109618.json"),
        f"{CVE_BASE}/2026/109xxx/CVE-2026-109619.json": read("CVE-2026-109619.json"),
        # A stand-in template response: the probe only checks that the file is there.
        f"{NUCLEI}/http/cves/2024/CVE-2024-27980.yaml": b"id: CVE-2024-27980\n",
        # The other ecosystems had nothing new in the window.
        **{f"{OSV_BASE}/{eco}/modified_id.csv": b"" for eco in SOURCES["osv"]["ecosystems"]
           if eco not in ("npm", "Packagist")},
    }  # fmt: skip
    opener = FakeOpener(routes)
    now = datetime(2026, 10, 26, 21, 30, tzinfo=UTC)
    result = run_fetch(
        settings,
        since=timedelta(hours=6, minutes=29, seconds=54, milliseconds=680),
        sources=("kev", "osv"),
        cve_ids=("CVE-2024-4577", "CVE-2024-27980"),
        opener=opener,
        now=now,
    )

    passed = sorted(t.advisory.id for t in result.triaged if t.passed)
    assert passed == ["CVE-2024-27980", "CVE-2024-4577", "CVE-2026-109618", "CVE-2026-109619"]
    assert result.malicious_packages == 4 and result.errors == []
    # The Node.js flaw was only "watch" (CVSS 8.1, not exploited) until the template turned up.
    node = next(t for t in result.triaged if t.advisory.id == "CVE-2024-27980")
    assert node.tier == "hunt now" and node.exploited == ["public Nuclei template"]
    assert result.triaged[0].advisory.id == "CVE-2024-4577"  # ranked: KEV, active, CVSS 9.8
    # A fresh KEV entry is merged with its CVE record: KEV flag from one, versions from the other.
    php = next(t.advisory for t in result.triaged if t.advisory.id == "CVE-2026-109618")
    assert php.kev_listed and php.kev_due_date.isoformat() == "2026-10-29"
    assert "8.4.27" in {r.fixed for p in php.affected for r in p.ranges}

    # Only templated URLs on allowlisted hosts; none of the links inside the records.
    references = {
        url
        for name in ("CVE-2024-4577.json", "osv-GHSA-84wq-86v6-x5j6.json")
        for url in (map_cve(record(name)) if name.startswith("CVE")
                    else map_osv(record(name))).references
    }  # fmt: skip
    assert references and not references & set(opener.urls)
    probes = set(opener.urls) - set(routes)  # the template probe's 404s, also templated
    assert probes and all(u.startswith(NUCLEI) and u.endswith(".yaml") for u in probes)

    inbox = result.inbox
    index = json.loads((inbox / "advisories.json").read_text(encoding="utf-8"))
    entry = index["CVE-2024-4577"]
    assert entry["triage"]["passed"] and entry["records"][0]["sha256"]
    assert (entry["triage"]["tier"], entry["triage"]["rank"]) == ("hunt now", 1)
    assert (inbox / entry["records"][0]["path"]).exists()
    log = (inbox / "requests.log").read_text(encoding="utf-8")
    assert "GET https://www.cisa.gov/" in log and f"GET {NUCLEI}/" in log

    found, day = find_advisory(settings.inbox_dir, "CVE-2024-4577")
    assert found["advisory"]["id"] == "CVE-2024-4577" and day == inbox
    assert top_candidates(settings.inbox_dir, 2) == ["CVE-2024-4577", "CVE-2026-109618"]


def test_a_failing_record_is_logged_not_fatal(settings, tmp_path):
    settings = settings.model_copy(
        update={
            "inbox_dir": tmp_path / "inbox",
            "sources_file": ROOT / "data" / "sources.toml",
            "watchlist_file": ROOT / "data" / "watchlist.toml",
        }
    )
    result = run_fetch(
        settings, since=timedelta(days=1), sources=(), cve_ids=("CVE-2099-0001",),
        opener=FakeOpener({}),
    )  # fmt: skip
    assert result.triaged == [] and "CVE-2099-0001" in result.errors[0]


@pytest.mark.parametrize(("text", "hours"), [("24h", 24), ("7d", 168), ("90m", 1.5)])
def test_parse_since(text, hours):
    assert parse_since(text) == timedelta(hours=hours)


@pytest.mark.parametrize("bad", ["24", "h", "1w", "-1d"])
def test_parse_since_rejects(bad):
    with pytest.raises(ValueError):
        parse_since(bad)
