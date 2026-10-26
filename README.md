# cti-to-detection-agent

A small agentic pipeline that reads a public threat report and turns it into validated STIX 2.1
intelligence, an ATT&CK coverage check and draft KQL hunts. A person approves every output
before it leaves the tool.

> **Status:** early build (M0). The full README, with diagram, threat model and evaluation
> results, comes with milestone M4.

```
report (local PDF / HTML / text)  or  fresh advisory (allowlisted feeds, no LLM)
  -> 1. Collector   LLM with NO tools; every item must carry a verbatim evidence quote
  -> 2. Validator   plain Python; rejects anything malformed, allowlisted or not quoted
  -> 3. Store       SQLite + STIX 2.1 bundle; provenance on every object
  -> 4. Analyst     ATT&CK mapping, coverage gaps, draft KQL hunts
  -> 5. Reviewer    second model scores each draft against a rubric
  -> 6. Human gate  approve / reject / edit; only approved items can be published
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
   (after normalisation), and the item's value must appear in its own quote.
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
python scripts/fetch_attack.py    # one-off download of the ATT&CK bundle
pytest
```

All rule names in `data/my_rules.sample.csv` are fictional.

## Licence

MIT
