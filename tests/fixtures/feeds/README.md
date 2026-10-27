# Feed fixtures

These are small samples of the real feeds, captured on 27 Oct 2026 with `Fetcher` from the hosts allowlisted in `data/sources.toml`. The tests serve them through a fake opener, so CI never touches the network.

| File | Source | Terms |
| --- | --- | --- |
| `kev.json` | CISA Known Exploited Vulnerabilities catalogue: the header and 3 entries | US government work, public domain |
| `CVE-*.json` | CVE List V5 records (CVEProject/cvelistV5) | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| `deltaLog-head.json` | The first 3 entries of cvelistV5 `cves/deltaLog.json` | as above |
| `osv-*.json`, `osv-*-modified_id.csv` | OSV.dev exports of GitHub Security Advisories | GitHub Advisory Database, [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) |

CVE-2024-4577 (PHP-CGI argument injection) and CVE-2024-27980 (Node.js `child_process` batch-file injection) are the historical gold cases for the pre-patch path. CVE-2026-109618 and CVE-2026-109619 are PHP RCEs that CISA added to KEV on 26 Oct 2026. CVE-2024-21762 (Fortinet FortiOS and FortiProxy SSL VPN out-of-bounds write, in KEV since February 2024) is the gold case for a product that isn't on the watchlist; its record gives "through" versions rather than fixed ones.
