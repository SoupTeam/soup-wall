# SOU-83 current-main integration evidence

This ledger describes the bounded create-only increment in PR #196, integrating
reviewed head `0f0031e35fae6ccf6dd9b5a4f6877b2ccc719203` with accepted main
`eb6aa6a531cef67a0eac307404da981a5a600f07`. It is not full SOU-83 completion.
Original create Ask remains unsupported/refused and broader typed-resource,
epoch/crash coverage and overhead limits remain explicit in the requirements
[audit](../../MCP_FILESYSTEM_CREATE_AUDIT.md).

`local-integration.json` retains exact implementation/test file hashes, local
check outcomes and failed diagnostic attempts. Candidate source was read-only,
writes confined to isolated scratch and networking restricted to loopback.
Raw logs, commands, credentials and process identities are not exported.

- Rust workspace: 1792 passed, 13 ignored environmental/native controls.
- Python script controls: 1525 total, no failures, 90 unavailable platform skips.
  The local harness additionally marks three unchanged Linux `/proc` switching
  controls unavailable on macOS. Native CI must run those original controls.
- Benchmark instrumentation unit tests: 66 total, 19 explicit skips.
- Clippy all workspace/all targets with `-D warnings`, rustfmt and documentation
  checks passed (277 Markdown files, 987 local links before this ledger).

The initial Rust failure in current-main provider readiness remains failed. An
independent owned-socket probe reproduced Darwin rejecting `SO_RCVTIMEO` after
peer close while the complete ACK and EOF were still readable. Nonblocking I/O
and `poll` now enforce the original host deadline/startup cap with exact ACK/EOF;
partial, extra, expired and missing-EOF controls remain refusals. Initial Python
setup failures and platform-inapplicable attempts are retained separately.

Local macOS results do not qualify the original Linux server, namespace,
publication or fault paths. Fresh current-source CI, CodeQL, candidate admission
and independent review remain required. Historical green CI/native artifacts in
the PR/audit qualify only their explicit earlier commits.
