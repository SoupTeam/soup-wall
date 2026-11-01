# SOU-207 Diagnostic Diff

## Goal

Add a private, offline comparison for two explicitly selected support bundles.

## Files

- `scripts/agent-diagnostic-diff.py`: bounded bundle reader and JSON/Markdown diff writer.
- `scripts/test_agent_diagnostic_diff.py`: synthetic bundle tests and side-effect checks.
- `docs/operations/AGENT_DIAGNOSTIC_DIFF.md`: installed-use guide and limits.

## Steps

1. Read only regular files below each selected bundle, with finite size, member, depth, and record limits.
2. Reject links, duplicate paths, unsafe archive members, malformed JSON, non-finite numbers, missing scope, and secret canaries.
3. Compare identity, selection, transport, daemon, storage, and reported failures while keeping missing, changed, and historical data separate.
4. Write bounded JSON and a self-contained Markdown report without raw prompts, tool results, credentials, or personal paths.
5. Test changed, stale, missing, corrupt, duplicate, unrelated, and secret-bearing inputs without starting children or using the network.

## Verification

- `python scripts/test_agent_diagnostic_diff.py`
- `python scripts/agent-diagnostic-diff.py --help`
