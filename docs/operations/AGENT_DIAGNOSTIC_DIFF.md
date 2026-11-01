# Offline diagnostic diff

`agent-diagnostic-diff.py` compares two selected support bundles. It reads regular JSON files only and writes a bounded JSON result plus a private Markdown report.

```text
python scripts/agent-diagnostic-diff.py BEFORE AFTER --json-out diff.json --markdown-out diff.md
```

The tool does not start a daemon, call a provider, use the network, follow links, execute report content, or upload data. It rejects unsafe paths, links, malformed data, non-finite values, missing scope, oversized bundles, duplicate-looking inputs, and secret-like content. A difference is evidence, not a root-cause or readiness claim.
