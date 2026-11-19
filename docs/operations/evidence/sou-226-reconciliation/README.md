# SOU-226 evidence

The local macOS real-process witness passed all 15 checks after 305 seconds of
actual downtime. It used real Console/Agent processes, production 300-second
ACK deadlines, no browser and no manual advance. Exact source-file and binary
hashes are in `sqlite-real-process.json`. The source commit is the accepted base
plus the explicitly hashed working snapshot; this is not a clean-commit claim.

`local-attempts.json` retains failed compilation attempts and subsequent passing
controls/build/witness commands with source and log hashes. PostgreSQL controls
are explicitly ignored locally; they require the dedicated PostgreSQL 16 CI
fixture. Local PostgreSQL 14 is not substituted for that qualification.

A subsequent diagnostic/shutdown refinement is covered by the final checks and
exact committed-source CI; the earlier local witness is attributed only to its
recorded source snapshot. No private process log, token, signing seed or database
connection string is published.

The first Draft run 41846138026 failed two generated-component equality checks:
the new profile steps had not been mirrored in ci-components.yml. The generated
copy is now synchronized; 13 component-contract and 30 documentation tests pass
locally, with 432 documents/1371 links checked. The complete CI Python suite
was also attempted locally; Linux child-process/subreaper controls do not pass
under macOS Seatbelt (7 failures, 4 skips), retained as an environment limitation.
The full CI Python suite must be confirmed on Linux, not reported green locally.

The entire workspace test suite and workspace/all-target Clippy -D warnings
passed at the recorded workspace-checks snapshot. A subsequent bounded-cycle
refinement pins a scan ceiling and is separately verified by SQLite controls
including two actual worker loops, shutdown and atomic restart regressions.
The updated PostgreSQL controls and real-process witness run on the final
implementation commit before acceptance is claimed.

Native run 41846137845 passed the new reconciliation controls and both real
305-second offline-gate witnesses. The run then failed the existing PostgreSQL
recovery demo because the two demos reused one source database and the same
unique synthetic tenant name. Reconciliation now has separate explicitly owned
disposable source/restore databases; neither demo touches the other's state.
This failed run remains a failed qualification, not an overall pass.

## Final qualification

[Native run 41850158512](https://github.com/SoupTeam/soup-wall/actions/runs/41850158512)
passed at exact implementation source bb091dd30c9b3fd2bae11a9b94df796b30a55481:
SQLite/PostgreSQL reconciliation controls (including two actual workers,
finite scan ceilings, restart, Owner races, duplicate ACKs, missing signer,
revocation and pause); both 305-second offline-gate witnesses (15/15 each);
and both encrypted recovery witnesses (31/31 each). No required PostgreSQL
control was skipped. Recovery inventory remains schema 30.

`native-final.json` retains the common 288-file source/binary identity once,
per-scenario configuration/checks and raw-report hashes. Every reported source
hash was independently compared with that exact Git commit before retention.
`native-attempt-1.json` permanently records the earlier failed run and its
individual successful/failed scenarios. Raw logs remain private.

This final update changes evidence only. Maintainer-owned current-main Ready,
security/admission and merge have not been performed by the author.

The final compatibility review also caught unconditional Console signal-handler
registration while reconciliation was disabled. It is now gated by the opt-in
flag. A real-process regression holds an authenticated HTTP body open, sends
SIGTERM and verifies the original disabled-mode signal exit, with child cleanup.
All reconciliation controls, fmt and Clippy pass after this change. Qualification
on this last runtime revision is recorded separately from the earlier bb091dd3
proof above.

## Last runtime revision qualified

[Run 41855697991](https://github.com/SoupTeam/soup-wall/actions/runs/41855697991)
passed at 759f43e82677fce8eb7f9c3beb95d945d2425bf3, including the real-process
disabled-worker SIGTERM regression, all SQLite/PostgreSQL controls, 15/15
real-offline checks per backend and 31/31 recovery checks per backend. The
current `native-final.json` binds this source and its binary/configuration
identities. The earlier successful bb091dd3 packet is retained separately as
`native-qualified-bb091dd3.json`; it is not substituted for the final source.
All 288 final source hashes were independently checked against Git.

The last runtime also passed the entire workspace and workspace/all-target
Clippy -D warnings and fmt. The SIGTERM witness was independently checked with
the compatibility guard removed: it fails with the expected graceful-drain
regression, then passes after restoring the exact committed source. That exit
101 is an expected negative mutation, not an unresolved test failure.
