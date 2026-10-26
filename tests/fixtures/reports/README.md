# Report fixtures

| File | What it is |
| --- | --- |
| `fixture-advisory.txt` | A fictional advisory written for the tests, with planted prompt-injection text. |
| `aa23-320a.txt` | The text of CISA advisory AA23-320A, *Scattered Spider* (updated 29 July 2025, TLP:CLEAR), as pypdf 6.21.2 extracts it from the PDF with SHA-256 `9bd8dbac5649bd36ae0303f0c61ca8026098d2877d89a1399cdfa83f35e742fd`. It's kept as text so the replay test doesn't depend on the pypdf version. |

`../llm/aa23-320a/` holds the responses `claude-haiku-5-5` actually returned for that text on
26 Oct 2026: outputs and token counts only. The request keys depend on the collector prompt
and on chunking. If either changes, delete the old files and record again from the text file:

```bash
cti-agent ingest tests/fixtures/reports/aa23-320a.txt --record tests/fixtures/llm/aa23-320a
```

`../attack-v20-subset-aa23-320a.json` is a slice of MITRE ATT&CK Enterprise v20.0, holding only the
techniques this advisory mentions. ATT&CK® is © The MITRE Corporation and is reproduced under the
ATT&CK terms of use.
