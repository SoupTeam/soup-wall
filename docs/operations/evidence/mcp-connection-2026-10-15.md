# MCP connection verification

Task: [SOU-50](https://linear.app/soup-wall/issue/SOU-50).
Date: October 15, 2026.

## Scope

The change adds transactional preview, connect, inspect and disconnect commands
for one selected Claude Code stdio MCP server. The implementation runs on Linux.
The installed Windows Claude Code client reaches the generated Linux entry
through an explicit Docker stdio bridge.

The tested source is `5de37450ec12fe0d0303d3728604114ef669e832`, based on
accepted main `f7b10d684a18305048ac8ab2d74e8206c2fcf3d9`. The tracked source
was clean, and the recorded source files and selected binary stayed unchanged
throughout the retained run.

## Results

All 68 acceptance checks passed. The receiver control first accepted an
unwrapped fixture request, confirming that the receiver was operational.
The two protected client sessions then produced exactly two useful read
executions and zero receiver requests.

| Scenario | Observed result |
| --- | --- |
| Preview | No config or metadata change |
| Connect and repeated connect | One native wrapper; original argument values preserved |
| Config preservation | Unrelated servers and settings retained |
| Controlled inspect probe | Admitted useful read; result digest retained |
| User edit conflict | Selected edit preserved; disconnect refused |
| Pending connect/disconnect records | Unknown until the operation was recovered |
| Malformed arguments and duplicate JSON keys | Refused |
| Actual client useful read | Original inventory text returned |
| Actual client forbidden send | Error returned; no server dispatch or receiver effect |
| Daemon loss after useful read | Subsequent call refused; no further execution |
| Child environment | Only PATH, HOME, USERPROFILE and runtime locale keys |
| Offline and repeated disconnect | Original selected entry restored |
| Cleanup | Agent stopped, private profiles removed, owned container removed |

The [structured report](mcp-connection-2026-10-15.json) retains all checks,
per-operation timings, actual-client outcomes, original execution frames and
source hashes. The [operator guide](../CLAUDE_MCP_CONNECTION.md) gives the
commands and recovery procedure.

## Environment And Timing

Linux x86-64 on WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`, Python 3.11.2,
Rust 1.99.0 and Claude Code 2.1.251. The Linux image is pinned to
`rust:1.99-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6`.
The fixture container had no external network and no published ports.

Successful connect operations took 2.26-2.37 seconds. Successful disconnects
took 7.22-23.25 ms. The two installed-client sessions took 1,953 ms and
1,094 ms. These are observed debug-build process durations, including setup
and binary hashing, rather than general latency guarantees.

Agent SHA-256:
`b6208d0a170255b0fc53dc85121e793abab4292adcb72ecb49375e6c25a90567`.
Registry SHA-256:
`a8cf35f613afa82bb4c10664ab04bc0fff110396369c801cbb6f1bf3c1e8980d`.
Client SHA-256:
`8d1229a281281b98fd2dee72b3253a704be4fce4d45207200cd32a9bb5a6c909`.

## Verification Boundaries

Fifteen new transaction tests passed, covering duplicate JSON fields, size
limits, unsafe paths, symlinks, hardlinks, FIFOs, permissions, concurrent
operations, outside edits, failed rename, invalid ownership records and
redaction of invalid native configuration values.
The existing 59 MCP admission, seven input and one proxy tests also passed.
Formatting and Agent Clippy with warnings denied passed.

The broader Agent suite on `a44662f` passed 475 tests with one ignored
live-model evaluation. The final error-redaction change then passed all 15
focused tests and the retained current-source acceptance run. An earlier
parallel broad attempt reported one resource-test daemon-startup failure;
the complete serial retry passed, without weakening that test.

The retained acceptance run used the real installed client with a deterministic
local Messages API. No model download, client update, paid provider call or real
user-profile edit was required. Native Windows/macOS transactions, arbitrary
server confinement and legacy HTTP-hook enforcement remain outside this result.
The legacy HTTP hook retains its documented fail-open behavior.
