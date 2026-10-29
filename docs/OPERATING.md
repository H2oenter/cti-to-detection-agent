# Operating cti-agent

This guide covers every command, where each one writes its results, what STIX the tool produces, and how approved objects reach Microsoft Sentinel.

Commands are for Windows PowerShell and run from the repo folder. Add `--help` to any command to list its options.

## The short version

```powershell
cti-agent fetch                        # new vulnerabilities since yesterday, ranked
cti-agent prepatch --top 5             # exposure queries for the 5 most urgent
cti-agent ingest reports\advisory.pdf  # when a threat report lands; prints a run ID
cti-agent analyse <run id>             # coverage gaps, draft hunts and a brief
cti-agent review <run id>              # you approve or reject each item
cti-agent publish <run id>             # a dry run; add --apply to send to Sentinel
```

Every command ends by printing where its results are:
- runs go to `out\<run id>\`;
- `fetch` writes to `reports\inbox\<date>\`.

All of this can also run from your phone, through a private Slack channel (section 12).

## 1. One-off setup

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
copy .env.example .env               # then add ANTHROPIC_API_KEY
python scripts\fetch_attack.py       # ATT&CK Enterprise + Mobile v20, checked by SHA-256
```

PowerShell may refuse to run `Activate.ps1`. If so, skip it and put `.venv\Scripts\` in front of each command instead, for example:
- `.venv\Scripts\cti-agent fetch`
- `.venv\Scripts\python scripts\gold_draft.py ...`

You need one or the other. Without either, Python can't find the tool and fails with "No module named cti_agent".

Other settings go in `.env`. All are optional:

| Setting | What it does |
| --- | --- |
| `ANTHROPIC_WORKSPACE_ID` | Only needed if your API key isn't scoped to a workspace. |
| `CTI_AGENT_REVIEWER` | The name the audit log records for your decisions. Default: your Windows user name. |
| `RULES_FILE` | Your detection rule list for the coverage check. Columns: `rule_name,technique_ids,tables`. Default: the fictional `data\my_rules.sample.csv`. At work, keep the real file outside the repo. |
| `EXTRACT_MODEL`, `ANALYSE_MODEL`, `REVIEW_MODEL`, `RECHECK_MODEL`, `REVIEW2_MODEL` | Which model does each job. |
| `RECHECK_INDICATORS` | Set to `false` to turn off the indicator re-check. |
| `MAX_TOKENS_PER_RUN` | A run stops cleanly before it would use more than this. Default: 300,000. |
| `ENDPOINT_APPROVED_FOR_AMBER` | Allows TLP:AMBER reports; see `ingest` in section 3. |
| `SENTINEL_WORKSPACE_ID`, `PUBLISH_AZURE_*` | Only for `publish --apply`; see section 10. |
| `SLACK_*` | Only for the Slack bot; see section 12. |

## 2. Daily: new vulnerabilities (the tool fetches them)

| Command | What it does |
| --- | --- |
| `cti-agent fetch` | Pulls the last 24 hours from CISA KEV, the CVE List and OSV, ranks every advisory, and checks the top 20 for a public exploit-scanner template. It uses no AI, contacts only allowlisted sites and never follows links found in advisories. |
| `cti-agent fetch --since 7d` | Uses a different window: `90m`, `24h` or `7d`. |
| `cti-agent fetch --all` | Lists every advisory, not just "hunt now" and "hunt soon". |
| `cti-agent fetch --source kev,cve` | Uses only some sources: any of `kev`, `osv`, `cve`. |
| `cti-agent fetch --id CVE-2024-21762` | Also pulls that CVE record. Repeat `--id` for more. |
| `cti-agent prepatch --top 5` | Writes pre-patch hunts for the 5 highest-ranked advisories of the last fetch, skipping any already done. It lists them and estimates the cost, then asks before going ahead. |
| `cti-agent prepatch --top 5 --yes` | The same without asking, for scheduled runs. |
| `cti-agent prepatch CVE-2024-21762` | Works on one advisory. It must be in the fetch inbox from any day, so fetch it first (with `--id` if needed). |

Each pre-patch run always writes an exposure query: it finds what runs an affected version, as Defender sees it. It also writes a behaviour hunt when the advisory gives something verifiable to look for.

Paste the exposure query into Defender advanced hunting or Sentinel and run it. Every hunt, exposure or behaviour, still goes through `review` (section 4) before it's kept as approved.

## 3. A threat report (you bring it)

Save the report into `reports\` yourself, as a PDF, HTML or text file. `ingest` only reads local files.

| Command | What it does |
| --- | --- |
| `cti-agent ingest reports\advisory.pdf` | Reads the report and extracts the actor, techniques, indicators and CVEs, each with the sentence it came from. It checks every item, writes a STIX bundle and prints a run ID. |
| `--tlp GREEN` | Sets the report's TLP: `CLEAR` (the default), `GREEN`, `AMBER`, `AMBER+STRICT` or `RED`. AMBER and AMBER+STRICT are refused unless `ENDPOINT_APPROVED_FOR_AMBER=true`. RED is always refused. |
| `cti-agent analyse <run id>` | Checks coverage against your rule list and drafts KQL hunts for the gaps. Two reviewers score each hunt, and it writes a brief. |
| `cti-agent analyse <run id> --force` | Analyses the run again. |

## 4. Review: you decide

| Command | What it does |
| --- | --- |
| `cti-agent review <run id>` | Walks you through every hunt, then every STIX object, one at a time. |
| `cti-agent review <run id> --all` | Shows already-decided items too, so you can change a decision. |
| `cti-agent review <run id> --item <ref> --approve` | Decides one item directly. See below for what `<ref>` is. |
| `cti-agent review <run id> --item <ref> --reject --reason "too noisy"` | Rejects one item. A rejection always needs a reason. |
| `cti-agent review <run id> --reviewer "Samuel"` | Records a different name for this session. |

`<ref>` takes one of two forms:
- **A hunt:** `draft:` followed by its file name without `.kql`.
- **A STIX object:** `stix:` followed by its id from `bundle.json`, for example `stix:indicator--1a940127-f01c-57af-a97a-b3f683f337fa`.

Keys during the walk-through:

| Key | Action |
| --- | --- |
| `a` | Approve. |
| `r` | Reject; it asks for a reason. |
| `e` | Edit a hunt's KQL or an object's JSON in your editor, then decide on the edited version. |
| `s` | Skip for now. |
| `q` | Quit. Decisions made so far are kept. |
| `A` | Approve the rest of this type. For actors, vulnerabilities and attack patterns, that's all the remaining ones. For indicators, it's only those that passed both checks with no warning, and you see them as a list first. |
| `R` | Reject the rest of this type, with one reason. Works for actors, vulnerabilities and attack patterns only. |

Hunts are never decided in bulk. A hunt that fails the KQL lint can't be approved until you edit it.

## 5. Send, and check what happened

| Command | What it does |
| --- | --- |
| `cti-agent publish <run id>` | **A dry run.** Writes the exact Sentinel requests to disk and sends nothing. |
| `cti-agent publish <run id> --apply` | Sends the approved objects to Sentinel with the publishing identity, after you confirm. |
| `--use-az-login` | With `--apply`: publish as yourself, after `az login`. |
| `--yes` | With `--apply`: don't ask to confirm. |
| `--reviewer "Name"` | Sets the name the audit log records. |
| `cti-agent audit` | Shows every decision and publish: who, when, which item, and why. |
| `cti-agent audit --run <run id> --verify` | Shows one run's history and checks that nobody has edited the log. It exits non-zero if the hash chain is broken. |
| `cti-agent trace <run id>` | Shows every model call in a run, with tokens, cost, time and outcome. |
| `cti-agent version` | Prints the version. |

## 6. Measuring the tool

| Command | What it does |
| --- | --- |
| `python scripts\gold_draft.py reports\x.pdf --stix reports\x-stix.json` | Starts an answer key (gold labels) for a report. `--stix` is the publisher's own STIX file, if there is one. |
| `python scripts\gold_draft.py --label eval\gold\x.draft.json` | Labels the draft: groups first, then one key per candidate. |
| `python scripts\gold_draft.py --finish eval\gold\x.draft.json` | Saves a draft you edited by hand. |
| `cti-agent eval --suite gold` | Scores the tool against your labels. It calls the model, at a few cents per report. |
| `cti-agent eval --suite injection` | Runs the reports with planted instructions and checks none got through. Costs about 15 cents live; free with `--replay tests\fixtures\llm\injection`. |
| `cti-agent eval` | Runs both suites. |

More `eval` options:
- `--replay` and `--record` (section 7);
- `--gold <folder>` and `--injection <folder>` for other inputs;
- `--results <folder>` for another output folder;
- `--no-write` to print the results without saving them.

## 7. Practice without spending anything

Every command that calls the model takes `--replay <folder>`, which reuses recorded answers instead. This walk-through costs nothing:

```powershell
cti-agent ingest tests\fixtures\reports\aa23-320a.txt --replay tests\fixtures\llm\aa23-320a
cti-agent analyse <run id> --replay tests\fixtures\llm\aa23-320a-analyse
cti-agent review <run id>
cti-agent audit --run <run id> --verify
cti-agent publish <run id>
```

`--record <folder>` saves live answers so you can replay them later. If you give both options the same folder, replay uses what's recorded and calls the model only for what's missing.

## 8. Where to see the results

Each command prints a summary and the folder it wrote to. To list your recent runs:

```powershell
Get-ChildItem out -Directory -Filter 2* | Select-Object -Last 10 Name
```

Run IDs start with the UTC time, so this lists the newest last:
- A report run looks like `20261027T172004Z-d5162f75-026c`: the time, the start of the report's SHA-256, then a random part.
- A pre-patch run has the advisory ID in the middle instead.

To open the files:
- `.md` files: VS Code's Markdown preview (Ctrl+Shift+V).
- `.kql` files: paste straight into Sentinel or Defender advanced hunting.
- `.json` files: any editor.

**After `ingest`**, in `out\<run id>\`:
- `bundle.json`: the STIX bundle (section 9).
- `validated.json`: every accepted item, with its quote and the text around it.
- `rejected.jsonl`: everything thrown out, with the reason (for example: not in the report, a placeholder, an injection attempt, not an indicator).
- `recheck.json`: the second model's verdict on each indicator, with its reason.
- `extraction.raw.json`: what the model returned, before any check.
- `provenance.json`, `run_summary.json` and `trace.jsonl`: the source and its hash, the counts, and every model call.

**After `analyse`**, in the same folder:
- `brief.md`: the one to read. It holds the coverage table, each hunt with both reviews, and a leadership summary.
- `hunts\*.kql`: one file per draft hunt. A comment header holds its evidence, reviews and lint findings.
- `analysis.json`: all of the above as data.

**After `prepatch`**, in its own `out\<run id>\`:
- `hunts\<CVE>-exposure.kql`: what runs an affected version, as Defender sees it.
- `hunts\<CVE>-exposure-cef.kql`, when it applies: appliances such as firewalls and VPN gateways that report an affected version in their own logs.
- `hunts\<CVE>-behaviour.kql`, when drafted: signs of exploitation.
- `brief.md` and `prepatch.json`: the summary, and when to retire the hunts.

**After `review`**:
- `out\<run id>\approved\stix-bundle.json`: only what you approved, plus the relationships between approved objects.
- `out\<run id>\approved\hunts\*.kql`: the approved hunts, ready for your change process.
- `out\audit.jsonl`: the decision log for all runs. Each entry is chained to the one before it by its hash.

**After `publish`** (dry run), in `out\<run id>\publish\<time>-sentinel-dry-run\`:
- `request-001.json` (then `request-002.json`, and so on): the exact request bodies, up to 100 objects each.
- `manifest.json`: the URL, the counts, and what was left out and why.

**After `fetch`**, in `reports\inbox\<YYYYMMDD>\`:
- `advisories.json`: every advisory with its tier, rank and reasons.
- `kev\`, `cve\` and `osv\`: the raw records. The index holds each one's SHA-256.
- `requests.log`: every URL fetched.

**After `eval`**:
- `eval\results\<date>.md` and `.json`: the gold scores.
- `eval\results\<date>-injection.md`: the injection results.
- `out\eval\<time>\`: the run behind each scored report, laid out like an `ingest` run.

Everything is also stored in the SQLite database `out\cti_agent.db`, in the tables `runs`, `objects`, `drafts` and `audit`.

## 9. The STIX you get

`bundle.json` is a STIX 2.1 bundle. STIX is a standard JSON format for threat intelligence, which Sentinel, MISP and OpenCTI all read.

For example, the SafePay advisory (AA26-293A) produced this bundle:

| Object | Count | What it is |
| --- | --- | --- |
| `threat-actor` | 1 | SafePay. |
| `indicator` | 19 | 9 IP addresses and 10 file hashes, each as a STIX pattern such as `[ipv4-addr:value = '104.26.2.223']`. |
| `attack-pattern` | 26 | One per ATT&CK technique, with its ID, link and tactic. |
| `vulnerability` | 5 | One per CVE in the report. |
| `relationship` | 50 | 19 `indicates` (indicator → actor), 26 `uses` (actor → technique) and 5 `targets` (actor → CVE). |
| `report` | 1 | The advisory itself, listing everything above. |
| `identity` | 1 | The tool, as the author of every object. |
| `marking-definition` | 1 | The TLP marking. |

The tool, not the model, draws the relationships, and only when the report names a single actor.

TLP:CLEAR appears as STIX's `TLP:WHITE` marking, because STIX 2.1's built-in markings predate TLP 2.0. The field `x_cti_agent_tlp` keeps the exact level.

Every object also records where it came from, in fields that start with `x_cti_agent_`:

| Field (after `x_cti_agent_`) | What it holds |
| --- | --- |
| `evidence_quote`, `evidence_page` | The exact text the item was checked against, and its page. |
| `evidence_kind` | `explicit` if the value is in that text. `inferred` if it isn't, such as a technique read from a described behaviour. |
| `source_file`, `source_sha256`, `source_kind` | Which document or feed, and exactly which version of it. |
| `model`, `prompt_version` | What read it. |
| `run_id`, `item_hash` | The run, and the fingerprint your approval is tied to. |
| `tlp` | The TLP you declared. |
| `attack_domain` | For attack patterns: Enterprise or Mobile ATT&CK. |
| `recheck_role`, `warnings` | For indicators: the re-check's verdict, and anything that needs a look. |
| `basis` | For relationships: why the tool drew the link. |

Here is one indicator from that bundle, trimmed:

```json
{
  "type": "indicator",
  "name": "104.26.2.223",
  "description": "SafePay victim intrusion.",
  "pattern": "[ipv4-addr:value = '104.26.2.223']",
  "pattern_type": "stix",
  "indicator_types": ["malicious-activity"],
  "valid_from": "2026-10-27T17:20:04.466777Z",
  "valid_until": "2027-01-25T17:20:04.466777Z",
  "x_cti_agent_evidence_quote": "104.26.2[.]223 SafePay victim intrusion",
  "x_cti_agent_evidence_page": 8,
  "x_cti_agent_source_file": "aa26-293a.pdf",
  "x_cti_agent_model": "claude-haiku-5-5",
  "x_cti_agent_tlp": "CLEAR"
}
```

Indicators expire 90 days after ingest (`valid_until`).

## 10. How it gets to Sentinel

1. **Approve in `review`.** Only approved objects can be sent. Each approval is tied to the fingerprint of what you approved: if an object changes afterwards, nothing is published until it's decided again.

   **Check shared infrastructure before you approve indicators.** In Sentinel, an indicator matches every event that involves its value. Reports sometimes list addresses of big shared services the attackers abused. In SafePay, for example, 140.82.114.4 is in GitHub's range and 173.194.194.94 is in Google's. If you approve those, the matching rules fire on ordinary traffic. Reject them with a reason such as "shared infrastructure".
2. **Run `cti-agent publish <run id>`.** This dry run sends nothing. It prints the counts and the start of the first request, and writes every request body to disk for you to read.
   - **Sent:** the indicators, attack patterns and threat actors you approved, the tool's identity, and the relationships between them. These are the types Sentinel's upload API accepts.
   - **Left out:** vulnerabilities, which the API doesn't accept. The dry run says so, and the manifest lists them.
   - **Never sent:** the report object, which isn't reviewed, and hunts, which stay in `approved\hunts\` for your change process.
   - **Refused:** anything marked TLP:RED. The whole publish stops.

   For SafePay with everything approved, that's 92 objects in one request:

   | Objects | Count |
   | --- | --- |
   | Indicators | 19 |
   | Attack patterns | 26 |
   | Threat actor | 1 |
   | Identity | 1 |
   | Relationships | 45 |

   The 5 `targets` relationships stay behind with the vulnerabilities.
3. **Set up the publishing identity, once.** It's the only identity in the design with write access: the **Microsoft Sentinel Contributor** role on one workspace, and nothing else. Choose one way to provide it:
   - **An app registration**, the normal way. Put `PUBLISH_AZURE_TENANT_ID`, `PUBLISH_AZURE_CLIENT_ID` and `PUBLISH_AZURE_CLIENT_SECRET` (or `PUBLISH_AZURE_CERTIFICATE_PATH`) in `.env`.
   - **Yourself**, for a pilot. Run `az login`, then add `--use-az-login`.

   Then finish the setup:
   - set `SENTINEL_WORKSPACE_ID` (the workspace GUID);
   - install the Azure library once: `pip install -e ".[azure]"`.

   There's no automatic fallback: the tool uses only the identity you chose.
4. **Run `cti-agent publish <run id> --apply`.** It asks you to confirm (the default answer is no), then POSTs each batch to:

   `https://api.ti.sentinel.azure.com/workspaces/<workspace id>/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview`

   How it sends:
   - up to 100 objects per request, with an Entra ID token;
   - tagged with the source name `cti-to-detection-agent`;
   - if Sentinel asks it to slow down (HTTP 429) or has a server error, it waits as told and retries, up to 6 tries;
   - it stops at the first hard failure, and batches already sent stay sent.

   What it records:
   - every batch in the audit log, including any object Sentinel rejected;
   - each batch as published in the database;
   - in the terminal, how many objects were uploaded and how many Sentinel rejected.
5. **Check in Sentinel.** The objects land in two Log Analytics tables:
   - indicators in `ThreatIntelIndicators`;
   - actors, attack patterns, relationships and the identity in `ThreatIntelObjects`.

   Each row's `Data` column holds the STIX object.

   ```kql
   // Indicators that arrived in the last day
   ThreatIntelIndicators
   | where TimeGenerated > ago(1d)
   | summarize arg_max(TimeGenerated, *) by Id
   | where IsDeleted == false
   | project ObservableKey, ObservableValue, ValidUntil, IsActive
   ```

   ```kql
   // Everything else that arrived, by type
   ThreatIntelObjects
   | where TimeGenerated > ago(1d)
   | summarize arg_max(TimeGenerated, *) by Id
   | where IsDeleted == false
   | summarize count() by StixType
   ```

   Sentinel re-sends all its threat intelligence to these tables every 7–10 days. That's why the queries keep only the latest row per `Id`.

   To narrow a query to this tool's uploads, decode the source name from `Id` the way Microsoft's examples do: `base64_decode_tostring(tostring(split(Id, '---')[0]))`.

   The objects should also show on Sentinel's threat intelligence page, with `cti-to-detection-agent` as the source.
6. **Turn on matching if you want alerts.** Uploaded indicators raise alerts only through analytics rules. The Threat Intelligence solution in Content hub has rule templates for this; their names start "TI map". Enable the ones for the log types you have.

### Not yet tried on a live workspace

The upload API is in preview, and `--apply` hasn't been run against a real workspace yet. Its requests, batching and error handling are tested against Microsoft's documented behaviour.

The first live upload will also show whether Sentinel keeps the `x_cti_agent_` fields in `Data`.

Microsoft's documentation:
- [The STIX objects upload API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api)
- [Working with STIX objects in Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/work-with-stix-objects-indicators)
- The tables: [ThreatIntelIndicators](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/threatintelindicators) and [ThreatIntelObjects](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/threatintelobjects)

## 11. What can run unattended

| Step | Unattended? |
| --- | --- |
| `fetch`, then `prepatch --top 5 --yes` | Yes, on a schedule, for example with Windows Task Scheduler. |
| `ingest` and `analyse` | You start them when a report arrives. |
| `review` | Never: a person decides. |
| `publish --apply` | You run it, after reading the dry run. |

## 12. Running it from Slack

`cti-agent slack` runs a bot in one private Slack channel. From there you can use the tool on your phone:
- upload a report;
- fetch new vulnerabilities;
- review;
- publish to Sentinel.

The bot runs on your machine and opens an outbound connection to Slack (Socket Mode), so there's no open port and no public URL. It answers only while `cti-agent slack` is running. If the machine sleeps, Slack says the command failed.

### One-off setup

1. **Install the Slack library:**

   ```powershell
   pip install -e ".[slack]"
   ```

2. **Create the Slack app.** At [api.slack.com/apps](https://api.slack.com/apps), choose **Create New App**, then **From a manifest**. Pick your workspace and paste [`docs/slack-app-manifest.json`](slack-app-manifest.json). It asks for the following bot scopes, and no others:

   | Scope | Why |
   | --- | --- |
   | `commands` | The `/cti` command. |
   | `chat:write` | Posting results. |
   | `files:read` | Downloading the reports you upload. |
   | `files:write` | Attaching the brief. |
   | `groups:history` | Seeing uploads in the private channel. |
   | `groups:read` | Checking at startup that the channel is private. |

3. **Make the app-level token.** Under **Basic Information → App-Level Tokens**, create a token with the `connections:write` scope. It starts `xapp-`.
4. **Install the app** to the workspace, then copy the **Bot User OAuth Token**. It starts `xoxb-`.
5. **Create the channel.** Make a private channel, for example `#cti-agent`, and invite the bot: `/invite @cti-agent`. Its ID is at the bottom of the channel's details and starts with `C`.
6. **Find your member ID.** It's in your Slack profile, under **⋯ → Copy member ID**.
7. **Add the settings to `.env`:**

   ```
   SLACK_BOT_TOKEN=xoxb-…
   SLACK_APP_TOKEN=xapp-…
   SLACK_CHANNEL_ID=C…
   SLACK_USERS=U0123ABC=Samuel
   ```

   For a team, list several members, comma-separated: `U0123ABC=Samuel,U0456DEF=Lee`.
8. **Check the setup**, then start the bot:

   ```powershell
   cti-agent slack --check
   cti-agent slack
   ```

   The check signs in to Slack and confirms the channel is private, not shared, and has the bot in it. The bot then runs until you press Ctrl+C.

Publishing from Slack also needs everything `publish --apply` needs (section 10): the `[azure]` extra, the app registration in `.env`, and `SENTINEL_WORKSPACE_ID`. Until those are set, Slack stops at the dry run and says what's missing.

### What you send, and what happens

| In the channel | What happens |
| --- | --- |
| `/cti help` | Lists the commands; only you see the reply. |
| `/cti runs` | The last 10 runs, each with a menu: Review, Publish dry run, Audit log. You don't have to type run IDs on a phone. |
| `/cti fetch` or `/cti fetch 7d` | Fetches and posts the top 10 advisories to hunt, with a **Pre-patch top 5…** button. |
| `/cti prepatch top 5` | Lists the advisories and what they'll cost. Nothing runs until you tap **Go ahead**. |
| `/cti prepatch CVE-2024-21762` | One advisory. It's fetched first if it isn't in the inbox. |
| Upload a report with the comment `ingest tlp:clear` | Downloads, ingests, then analyses it. Posts the counts, the leadership summary and `brief.md`, with **Review** and **Publish dry run** buttons. The TLP is required: `clear`, `green`, `amber` or `amber+strict`. |
| `/cti analyse <run>` | Analyses a run again, if the spend cap or an error stopped it. |
| `/cti review <run>` | Posts review cards in a thread (see below). |
| `/cti publish <run>` | A dry run: counts, what's left out, and where the requests are. **Publish N…** then opens a confirm that names the count and the workspace. |
| `/cti audit <run>` | The run's last 25 decisions and the chain check. |

Long jobs post one message that moves from Queued to Running to Done. When a job finishes, the bot also replies with an @-mention, so your phone gets a notification.

### Reviewing on a phone

- **Hunts:** one card each, with the scores from both reviewers, the evidence, the start of the query (the whole query is attached when it's long), and **Approve** and **Reject…** buttons. A hunt that fails the lint has no Approve button: edit it in the terminal.
- **Indicators that passed both checks:** one list, with **Approve these N** behind a confirm, and **One by one**.
- **Flagged indicators:** one card each.
- **Actors, vulnerabilities and attack patterns:** one list each, with **Approve all N**, **Reject all N…** and **One by one**.
- **Reject** opens a box for the reason, which goes in the audit log.

Nothing is approved unseen:
- **A list or query too long for a card** is posted whole as a file just above it.
- **If the file can't be posted,** or a card's warnings are too long to show whole, the card has no Approve button. Review that item in the terminal.

Each decision is logged as `slack:<member ID> (<name>)`. Some taps change nothing:
- **The item changed after the card was posted** (for example, someone edited it in the terminal): the tap decides nothing and says so. Run `/cti review` again.
- **A second tap:** it logs nothing.
- **A list that changed since it was posted:** it decides nothing.
- **A run Slack may no longer show** (for example, `SLACK_APPROVED_FOR_AMBER` was turned off): the tap decides nothing and points you to the terminal.

A job that failed or stopped, such as an upload Sentinel refused, can be started again with the same button once the cause is fixed. A job that finished says so instead of running twice.

### What Slack never sees, and what stays in the terminal

- **Live indicators:** values are defanged (`104[.]26[.]2[.]223`, `hxxps://`), and link previews are off.
- **Report content beyond its TLP:**

  | TLP | What Slack sees |
  | --- | --- |
  | CLEAR, GREEN | Content. |
  | AMBER | Refused, unless `SLACK_APPROVED_FOR_AMBER=true` says this channel is approved for it. |
  | AMBER+STRICT | Counts only. |
  | RED | Refused before download, and the bot asks you to delete the file from Slack. |

- **What only the terminal can do:**
  - edit a hunt or an object;
  - change a decision (`review --all`);
  - publish with `--use-az-login`;
  - review a run whose content Slack can't show.
- **Spend:** the bot won't start a job that would take today's model spend (UTC, across every interface) past `SLACK_DAILY_SPEND_CAP_USD`, which defaults to $5.

The bot hasn't yet been run against a live Slack workspace. Its logic is tested end to end against a fake Slack, and its Slack wiring offline.
