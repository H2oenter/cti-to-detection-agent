"""Feed fetching, mapping and triage, against recorded real feed samples. No network."""

import io
import json
import urllib.error
from datetime import UTC, datetime, timedelta

import pytest
from conftest import FIXTURES, ROOT

from cti_agent.feeds.fetch import find_advisory, parse_since, run_fetch
from cti_agent.feeds.http import FeedError, Fetcher, _AllowlistRedirects, build_url, load_sources
from cti_agent.feeds.sources import (
    cve_record_url,
    map_cve,
    map_kev,
    map_osv,
    recent_cve_ids,
    recent_osv_ids,
)
from cti_agent.feeds.triage import load_watchlist, triage

FEEDS = FIXTURES / "feeds"
SOURCES = load_sources(ROOT / "data" / "sources.toml")
WATCHLIST = load_watchlist(ROOT / "data" / "watchlist.toml")
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
CVE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def read(name):
    return (FEEDS / name).read_bytes()


def record(name):
    return json.loads(read(name))


class FakeOpener:
    """Serves fixture bytes by URL and remembers every URL asked for."""

    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def open(self, request, timeout=None):
        self.urls.append(request.full_url)
        if request.full_url not in self.routes:
            raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)
        return io.BytesIO(self.routes[request.full_url])


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
    ("name", "passed", "product"),
    [
        ("CVE-2024-4577.json", True, "PHP"),
        ("CVE-2024-27980.json", True, "Node.js"),
        ("osv-GHSA-84wq-86v6-x5j6.json", False, "PHP"),  # Composer package, but a DoS
    ],
)
def test_triage(name, passed, product):
    adv = map_cve(record(name)) if name.startswith("CVE") else map_osv(record(name))
    result = triage(adv, WATCHLIST)
    assert result.passed is passed
    assert result.product.name == product


def test_kev_entry_off_the_watchlist_fails():
    arista = map_kev(record("kev.json")["vulnerabilities"][2])
    result = triage(arista, WATCHLIST)
    assert not result.passed and result.product is None and result.signals == ["CISA KEV"]


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
    }
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
    assert set(opener.urls) <= set(routes)

    inbox = result.inbox
    index = json.loads((inbox / "advisories.json").read_text(encoding="utf-8"))
    entry = index["CVE-2024-4577"]
    assert entry["triage"]["passed"] and entry["records"][0]["sha256"]
    assert (inbox / entry["records"][0]["path"]).exists()
    assert "GET https://www.cisa.gov/" in (inbox / "requests.log").read_text(encoding="utf-8")

    found, day = find_advisory(settings.inbox_dir, "CVE-2024-4577")
    assert found["advisory"]["id"] == "CVE-2024-4577" and day == inbox


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
