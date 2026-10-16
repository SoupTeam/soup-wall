# Constrained native MCP create-file verification — 2026-10-15

SOU-54, Phase 1 reviewed write semantics and Phase 2 execution authority.
Accepted base: `c2c9355c1f754daedcd7f31860ede08a21169fe2`.
Final runtime and build source: `4931c21781413e84ab15ede8dc13cf232639aa4d`.
The later evidence-only delivery does not change these runtime inputs.
Independent review and exact-head hosted CI remain acceptance gates; this is an
internal bounded candidate, not product release or general host certification.

[Operator contract and runnable commands](../MCP_CREATE_FILE.md),
[machine-readable source, configuration and outcomes](MCP_CREATE_FILE_2026-10-15.json),
[raw sanitized witnesses](MCP_CREATE_FILE_2026-10-15.raw.tar.gz),
[archive members and SHA-256](MCP_CREATE_FILE_2026-10-15.raw-manifest.json).

## Actual execution and refusal

| Boundary | Observed result |
| --- | --- |
| Real enforcing daemon and stdio MCP, 26 cases | 26 passed, 0 failed, 0 skipped |
| Authenticated native transport and stdio races, 8 cases | 8 passed, 0 failed, 0 skipped |
| Linux Agent unit tests | 241 passed, 0 failed, 0 ignored |
| Linux native endpoint tests | 39 passed, 0 failed, 0 ignored |
| Final macOS Agent/MCP/native regression selection | 337 passed, 0 failed, 0 ignored |
| Independent Python evidence-grading controls | 24 passed, 0 failed |

Linux runs used UID/GID 65532, zero effective capabilities, `NoNewPrivs: 1`,
seccomp and Docker `--network=none`; only owned loopback daemon/proxy traffic was
available. Environment: aarch64, kernel `6.12.76-linuxkit`, overlayfs, Rust 1.98.1,
Python 3.11.2. The builder is pinned in the retained Dockerfile. Final image ID:
`sha256:737c5120bdfe2ca1dd84dbf550df3bc7d21a128df37d8a2d351dbb83854dc6f6`.
Agent binary SHA-256:
`64b024760df207e649725f3709671791980d0a9bb8c69ffc20d3a08868934df7`.
Both drivers retained clean identical source snapshots and unchanged binary
hashes through completion; every private fixture and owned container was removed.

A permitted exact `write` received ordinary native Allow before the broker
created a complete UTF-8 file with mode `0600` and one link. The original path,
arguments and JSON-RPC ID remained correlated. Existing targets, symlinks, hard
links, FIFOs, directories, traversal, nested/missing parents, unlisted targets,
ambiguous spellings, wrong server ID and a mismatched cwd-selected workspace
produced no create effect. Both native and classifier Ask/Deny were enforced
before execution. Seventy repeated existing-target refusals retained useful
same-session reading and clean collector/child EOF.

The transport race fixture forwards genuine authenticated daemon requests and
responses; it never fabricates Allow. Destination/content substitution retained
the original execution binding and was denied by the real daemon. Replacing the
root after genuine Allow and before its receipt reached the broker changed
neither the original nor the replacement root. The fixture separately records
its own root rename/restoration, then requires useful same-session continuation.
Two independently admitted sessions racing for one target produced exactly one
complete file and one losing execution error, followed by useful reads in both
sessions. A replay retained the first committed file and did not execute twice.
Unsupported batch, queued overlap and cancellation were explicitly refused;
those protocol refusals terminate that session and are followed by a useful
**fresh** session, rather than being reported as same-session recovery.

Independent tree snapshots cover workspace/outside file types, inode/device,
mode, links and content digests. The discovery child records startup, raw input,
output, EOF and a separate tools/call ledger. Released client bytes, actual native
audit and broker effect records must agree with these witnesses. Zero child calls
alone never establishes zero broker execution. The result-withholding case
requires the successfully committed file to remain present; a withheld receipt
cannot roll back filesystem effects.

## Bounds, latency and preserved failures

The initial supported profile permits one explicitly allowed direct child of the
pinned root, at most **4,096 UTF-8 bytes**, including empty content. This permits
complete inspection by the installed real rule baseline. A larger 65,536-byte
candidate was conservatively interrupted when the classifier truncated its input
and returned Unknown. The bound was narrowed; Unknown/Ask was not overridden.
This is not a guarantee that arbitrary content receives Allow.

The final stdio matrix observed **0 false interruptions in 4 deliberately useful
creation cases**. It contains 95 create-call samples because repeated-failure
coverage submits 70 calls: median 0.594375 ms, p95 68.590792 ms, maximum 90.431083 ms.
These are scripted client-to-correlated-response timings for a local debug build,
including classifier, native policy and filesystem work. Pre-classification
refusals dominate the median; these are not isolated executor overhead or
production throughput/durability estimates. Race durations are retained per case.
The expected unsupported-protocol terminations are reported separately.

Original red evidence is retained without relabeling it as passed:

1. `c62fec1`: the first 22-case client used unsupported string progress tokens.
   All calls failed before execution; the fixture was corrected to the existing
   supported integer form, preserving original string JSON-RPC IDs.
2. Runner `d242137` with the unchanged `c62fec1` Rust binary: 21/22 passed; the
   65,536-byte case honestly returned unconfirmed Ask. The 4,096-byte profile
   revision is `2b4a77a`.
3. Runner `07e1363` with the `2b4a77a` Rust binary: 22/26 passed. Wrong server ID,
   cwd-selected workspace and two normalized path aliases incorrectly created
   files in the disposable pre-review candidate. Final source `4931c21` adds
   explicit selected-session identity and original-spelling checks. All four
   original negative cases now pass with zero create effects.

The two intermediate runner-only revisions leave their recorded binary's Rust
inputs unchanged; their build and runner commits are listed separately. Final
acceptance above uses a binary built from the same exact final runtime revision.
Two preliminary Docker build attempts did not reach test execution: release
`.dockerignore` excluded required test fixtures and a broad temporary Dockerfile
location encountered an unrelated inaccessible socket file. A dedicated owned
Git-archive context and test-specific ignore file resolved both; the final
Dockerfile, ignore and run harness are in the archive. No test was skipped or
weakened to resolve these failures.

## Repository checks and limits

Formatting, warnings-denied workspace/all-target Clippy, workflow actionlint and
local documentation links passed. Before the final boundary repairs, the full
macOS workspace run on `c62fec1` passed 1,059 tests with nine existing opt-in
records: live local model, Redis, restored outbox, PostgreSQL control plane,
webhook child/long recovery fixtures, PostgreSQL webhook recovery, real OIDC and
real SAML metadata. The final affected Agent/MCP/native selection and Clippy were
rerun on `4931c21`; full final-source workspace/platform checks remain hosted-CI
gates.

The initial full Python suite ran 525 tests with 26 skips: five optional
Playwright checks, 15 selected Linux TLS runtime checks, five native Windows
checks and one explicit Docker permissions opt-in. Benchmark helpers ran 44 tests
with 16 individual and two class-level skip records. No model assets, external
provider credentials or optional AgentDojo environment were used. All 24 new
core evidence controls were rerun on final source without skips.

macOS and Windows explicitly refuse this new create executor; positive execution
is Linux-only. Unit fault injection independently checks partial anonymous
writes, abandonment, pre-publication failure, root/target replacement and honest
post-publication directory-sync failure. It does not claim that every OS failure
was induced through stdio. Filesystem type alone is insufficient: the required
`O_TMPFILE`, link and sync syscalls must succeed, with no named staging fallback.
Root-inode authority cannot prevent a same-UID operator relocating that inode
after the final identity check. Cancellation after atomic publication and result
withholding cannot undo already committed bytes. The discovery server remains
operator trusted for startup; arbitrary server containment is outside this task.

The v1 read contract remains unchanged. SOU-48 approval storage, redemption,
endpoints and CLI were not modified; unconfirmed Ask remains blocked.

Raw archive SHA-256:
`9c1b6c129b802655b80cf21e30485725a67c72c0cb2be2ba199216943bcba19d`.
All 22 archive members were independently checked by byte count and digest.
Runtime input manifest SHA-256:
`14ee687388084b64ba04ca07bc633e987b7d3b7c85ddb0313cf8fea3236be947`.
No Agent credential values, customer inputs or private runtime homes are included.
