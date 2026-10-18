# SOU-84 owned Linux acceptance, 2026-10-18

This is sanitized evidence from the opt-in Agent audit retention candidate.
The raw self-test workspace, audit segments, export, HTML, logs and synthetic
sentinel remain in an owner-only Linux directory and are not committed or
uploaded. Reproduce the run with
[`AGENT_AUDIT_RETENTION.md`](../../AGENT_AUDIT_RETENTION.md#reproduce-the-owned-acceptance).

## Exact candidate identity

- Accepted starting main: `1f0207d313b4840d38719d1109868afabe4cdb20`.
- Runtime source-file SHA-256: `f70d09b9b5a0767f6d6e842bdcd18393d23966ad82ec46482b0eb7bded50e869`.
  `SOURCE_PATHS` and the filename-delimited hashing procedure are in
  `scripts/sou84_owned_acceptance.py`. The candidate staged diff was applied
  unchanged to a Linux ext4 checkout with LF source bytes.
- Linux Agent binary SHA-256: `0b9f0cf5ae03a35293add39c44f10d6a17e5c71b27cd022578f58a1be2714071`.
- Owned Agent configuration SHA-256: `d91bd09bdb7d67a54d1d41922ef429c48ade42c0bebe7bdf9610360ed1851df5`.
- Private export SHA-256: `437c3c7ed4184cd9ca1392db08e098e022e3a70676c45319de8bcfe25e8d90cb`.
  Private HTML SHA-256: `6d22f65ec235901783e0bbbfeaa90a5675b2e4c244fdad3e27d58db731207a03`.

## Witnesses and limits

| Observation | Result |
| --- | ---: |
| Real native MCP self-test positive/negative scenarios | 5/5 passed, no skip |
| Authenticated daemon hook requests across two starts | 440 |
| Segments created / retained / intentionally pruned through | 12 / 4 / 8 |
| Records in verified private export and allowlisted report | 139 |
| Highest observed owned disk bytes / configured cap | 258,890 / 512,000 |
| Kernel `VmHWM` across owned daemon runs / tested ceiling | 24,504 / 262,144 KiB |
| Browser large-history initialization / filter | 252 / 167 ms at 10,000 events |

The browser check opened this owned report and confirmed the retention notice,
filters, pagination, keyboard details, small-screen layout, inert injected
text and zero network requests. Rust regression tests cover concurrent events,
interrupted publication and prune, failed/short writes, `ENOSPC`, recovery,
oversized records, missing or altered segments, and replaced files/directories.
The retained native result test observed `native_audit_unavailable` and no
result release when its sink was faulted.

## Regression checks

- `cargo fmt --all -- --check` and workspace/all-target Clippy with `-D warnings`: passed.
- Locked workspace Rust tests on the ext4 checkout: 1,457 passed, 13 existing
  ignored, zero failures, with the unrelated
  `wrapped_argument_limit_is_checked_before_writing` test explicitly skipped.
  That test requires `/usr/bin/env` to have one link; this Ubuntu resolves it
  to a coreutils multi-call executable with 115 links. The production
  executable guard correctly refuses it. The same test must still run in CI.
- Python script suite: 780 passed, 35 environment skips. Python benchmark
  suite: 62 passed, 19 environment skips. Documentation: 190 Markdown files,
  737 local links, zero errors.
- The Chromium check against the generated owned report passed CSP, no-network,
  injected-text inertness, filters, keyboard details, paging, small-screen and
  10,000-event responsiveness checks.

These digests detect differences in the recorded candidate inputs and outputs;
they do not authenticate local history against an owner who can alter both
data and metadata. The controlled native fixture has no live model. Allow
does not prove external execution, and a result release does not prove model
consumption. The legacy host hook remains best effort on audit write errors.
