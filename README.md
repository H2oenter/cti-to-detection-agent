# cti-to-detection-agent

A small agentic pipeline that reads a public threat report and turns it into validated STIX 2.1
intelligence, an ATT&CK coverage check and draft KQL hunts. A person approves every output
before it leaves the tool.

> **Status:** `ingest`, `analyse`, `fetch` and `prepatch` work end to end against the real
> models, and the tests replay those recorded runs offline. The human gate (`review`) and
> `publish` come next. The full README, with diagram, threat model and evaluation results,
> comes with milestone M4.

```
report (local PDF / HTML / text)
  -> 1. Collector   LLM with NO tools; every item must carry a verbatim evidence quote
  -> 2. Validator   plain Python; rejects anything malformed, allowlisted or not quoted
  -> 3. Store       SQLite + STIX 2.1 bundle; provenance on every object
  -> 4. Analyst     coverage gaps against a rule set, draft KQL hunts, deterministic KQL lint
  -> 5. Reviewer    a separate model call scores each draft; code decides what needs attention
  -> 6. Human gate  approve / reject / edit; only approved items can be published

fresh advisory (KEV, OSV, CVE List: allowlisted, no LLM) -> triage (watchlist + RCE signal)
  -> exposure query (written by code from version data) + behaviour hunt (analyst + reviewer)
  -> retire when patched, or after 30 days
```

## Design rules

1. **Untrusted input is data, never instructions.** Report text reaches the model inside
   `<untrusted_report>` tags, and the system prompt says any instructions in it are to be ignored.
2. **The model that reads raw reports has no tools.** It gets one structured-output call: no
   tools, no network, no files.
3. **No following links.** Input is a local file, or an item `fetch` pulls from a fixed
   allowlist of feed endpoints. Links found inside reports or feed items are recorded and
   never fetched.
4. **Evidence or it didn't happen.** Every item's quote must appear verbatim in the source
   (after normalisation), and the item's value must appear in its own quote. Evidence taken
   from text addressed to an AI ("ignore previous instructions...") is rejected as a
   suspected injection.
5. **Read widely, write narrowly.** `publish` is the only command that sends data anywhere.
   It runs as a dry run unless you pass `--apply`.
6. **Least privilege.** Queries use one read-only identity. `publish` uses a separate one.
7. **Secrets never touch the repo.** They live in `.env` (gitignored), with `.env.example`
   as the template.
8. **Everything is auditable.** Approvals and publishes go to an append-only log.

## Quick start

```bash
py -3.12 -m venv .venv            # or: python3.12 -m venv .venv
.venv/Scripts/activate            # or: source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env              # then add ANTHROPIC_API_KEY
python scripts/fetch_attack.py    # one-off: ATT&CK Enterprise + Mobile v20, SHA-256 pinned
pytest

cti-agent ingest reports/aa23-320a.pdf --tlp CLEAR   # stages 1-3: extract, validate, store
cti-agent analyse <run_id>                           # stages 4-5: coverage, hunts, review, brief
cti-agent fetch --since 24h                          # fresh advisories, triaged (no LLM)
cti-agent prepatch CVE-2024-4577                     # exposure + behaviour hunt until patched
cti-agent trace <run_id>                             # tokens, cost and outcome per step
```

Every run writes `out/<run_id>/`:
- `ingest`: the raw model output, the accepted items with their surrounding source text, `rejected.jsonl` with a reason for each rejection, a validated STIX 2.1 `bundle.json` and `trace.jsonl`.
- `analyse` and `prepatch`: `hunts/*.kql`, each with its evidence, review scores and lint results in a header, plus `brief.md`.

`fetch` files raw records, with their SHA-256 and the list of URLs requested, under `reports/inbox/`.

Model responses can be recorded with `--record` and replayed with `--replay`. Pass both with the same folder to replay what's recorded and fetch only what's missing.

KQL drafts are never run by the tool. A lint built from Microsoft's table references (`data/kql_schema.json`) rejects anything that could leave the workspace, such as `externaldata`, `http_request`, code plugins and cross-workspace queries, before a person is asked to run a query.

All rule names in `data/my_rules.sample.csv` are fictional.

## Licence

MIT
