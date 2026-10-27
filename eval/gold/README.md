# Gold labels: how to label a report

A gold file says what a person, not the tool, believes a report contains. `cti-agent eval` scores the pipeline against it. Labelling takes about 20–30 minutes per report with the helper.

## Steps

1. Put the report, and CISA's STIX JSON for it if there is one, in `reports/`.
2. Run the helper. It's deterministic: no model and no network.
   ```bash
   python scripts/gold_draft.py reports/aa26-222a.pdf --stix reports/aa26-222a-stix.json
   ```
3. Open `eval/gold/<id>.draft.json` with the report beside it. The helper has already:
   - pre-filled `gold.indicators` with values found in **both** the text and CISA's STIX;
   - pre-filled `gold.techniques` with every technique ID printed in the text;
   - left everything else in `indicator_candidates.text_only` for you to decide.
4. Apply the rules below. Then fill in `title`, `source.url`, `actors`, `labelled_by` and `labelled_on`, and save the `gold` section on its own as `eval/gold/<id>.json`.
5. Don't run the tool on the report or look at its output until you've finished labelling. Labels have to be independent of the thing they measure.

## Rules

**Indicators** are values the report presents as indicators of *this* activity, printed in the report text. The kinds are `ipv4`, `ipv6`, `domain` (including `.onion`), `url`, `sha256`, `sha1`, `md5` and `email`.
- **Include:** attacker IPs, domains, URLs, file hashes, and contact emails the actors used, such as ransom-negotiation addresses.
- **Leave out:**
  - reference and footnote links;
  - the authoring agencies' contact addresses;
  - naming-pattern placeholders such as `targetsname-sso.com`;
  - legitimate tools and services the actors abused, such as `fleetdeck.io` or `mega.nz`;
  - file names;
  - hostnames.
- **Values only in the STIX file:** leave them out. The model only reads the text. The helper lists them under `stix_only` so you can see them.
- **`optional_indicators`:** for values you think are defensible either way, such as a legitimate service the report explicitly names as exfiltration infrastructure. The eval counts them neither for nor against the model.
- **Values:** write them refanged (`1.2.3.4`, not `1.2.3[.]4`). The eval normalises case and defanging the same way the validator does.

**Techniques**
- **`techniques` (required):** IDs the report attributes to the actor's behaviour, in the text or in the ATT&CK tables.
- **`optional_techniques`:** IDs that describe a tool's capabilities rather than what the actors were seen doing, such as a stealer's feature list (in AA23-320A, Raccoon Stealer's T1217 and T1539).
- **Ignore** tactic IDs (`TA00xx`).
- **Matching is exact:** `T1566` doesn't match `T1566.004`.

**Actors and CVEs** are written as the report writes them. These are recorded for reference; the scores cover indicators and techniques.

**Pinning:** `source.sha256` ties the labels to one version of the report. CISA updates advisories, so if the file changes, the eval refuses to score until the labels are checked again.

## Format

```json
{
  "report_id": "aa26-222a",
  "title": "#StopRansomware: Gunra Ransomware",
  "source": {"url": "https://www.cisa.gov/...", "file": "reports/aa26-222a.pdf", "sha256": "…"},
  "labelled_by": "Samuel Omiwole",
  "labelled_on": "2026-11-02",
  "indicators": [{"kind": "ipv4", "value": "…"}],
  "optional_indicators": [],
  "techniques": ["T1190"],
  "optional_techniques": [],
  "actors": ["Gunra"],
  "cves": ["CVE-2024-55591"],
  "notes": "anything a reader of the results should know"
}
```
