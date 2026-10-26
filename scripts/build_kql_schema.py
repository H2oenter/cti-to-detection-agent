"""Build data/kql_schema.json from Microsoft's published table references.

Run from the repo root:  python scripts/build_kql_schema.py

A one-off setup step. The result is committed; the KQL lint reads it offline to
check that drafted hunts only use real tables and columns.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from bs4 import BeautifulSoup

DEFENDER_URL = "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-{slug}-table"
AZURE_MONITOR_URL = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/{slug}"

DEFENDER_TABLES = [
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceLogonEvents",
    "DeviceRegistryEvents", "DeviceEvents", "DeviceImageLoadEvents", "DeviceInfo",
    "DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities", "EmailEvents",
    "UrlClickEvents", "CloudAppEvents", "IdentityLogonEvents",
]  # fmt: skip
AZURE_MONITOR_TABLES = [
    "SigninLogs", "AADNonInteractiveUserSignInLogs", "AuditLogs", "OfficeActivity",
    "W3CIISLog", "CommonSecurityLog",
]  # fmt: skip
# Defender tables streamed into Sentinel gain the standard Log Analytics columns.
LOG_ANALYTICS_COLUMNS = {
    "TimeGenerated": "datetime",
    "TenantId": "string",
    "Type": "string",
    "SourceSystem": "string",
}
DEST = Path("data/kql_schema.json")


def columns_from(url: str) -> dict[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "cti-to-detection-agent/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        soup = BeautifulSoup(response.read(), "html.parser")
    for table in soup.find_all("table"):
        heads = [th.get_text(strip=True).lower() for th in table.find_all("th")]
        if heads and heads[0] in ("column name", "column"):
            columns = {}
            for row in table.find_all("tr")[1:]:
                cells = [td.get_text(strip=True) for td in row.find_all("td")]
                if len(cells) >= 2 and cells[0]:
                    columns[cells[0]] = cells[1].lower()
            return columns
    raise ValueError(f"no column table found at {url}")


def main() -> int:
    tables = {}
    for name in DEFENDER_TABLES:
        url = DEFENDER_URL.format(slug=name.lower())
        columns = columns_from(url)
        added = [c for c in LOG_ANALYTICS_COLUMNS if c not in columns]
        columns.update({c: LOG_ANALYTICS_COLUMNS[c] for c in added})
        tables[name] = {"product": "defender-xdr", "source": url, "columns": columns,
                        "added_for_sentinel": added}  # fmt: skip
        print(f"{name}: {len(columns)} columns")
    for name in AZURE_MONITOR_TABLES:
        url = AZURE_MONITOR_URL.format(slug=name.lower())
        columns = columns_from(url)
        tables[name] = {"product": "sentinel", "source": url, "columns": columns}
        print(f"{name}: {len(columns)} columns")

    schema = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generated_by": "scripts/build_kql_schema.py",
        "note": "Column lists copied from Microsoft Learn table references. Re-run to refresh.",
        "tables": tables,
    }
    DEST.write_text(json.dumps(schema, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"Wrote {DEST} ({len(tables)} tables)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
