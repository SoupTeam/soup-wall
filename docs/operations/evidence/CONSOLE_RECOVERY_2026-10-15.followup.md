# Console recovery CI portability follow-up — 2026-10-15

SOU-49, [PR #120](https://github.com/SoupTeam/soup-wall/pull/120). Runtime source:
`423dfab0889728199765285567c55884350f4ad2`. This supplements the
[original immutable evidence](CONSOLE_RECOVERY_2026-10-15.md); original outcomes and
red witnesses remain retained. Both repeat runs began with a clean worktree and
verified unchanged runtime input/binary hashes through complete cleanup.

## Repairs and independent negative control

The [initial workflow](https://github.com/SoupTeam/soup-wall/actions/runs/38683422926)
was rejected before execution: job-level `env` cannot use `runner.temp`.
The build target now uses the supported `github.workspace` context; actionlint 1.7.12
passes. The new workflow explicitly executes the real Linux file-ownership regression.

The recovery driver intentionally creates host files with mode `0600`. On native Linux,
a host certificate owned by the runner cannot be read by the PostgreSQL container UID.
The reused disposable OIDC database helper now copies **both** mounted TLS files into
private container paths and assigns PostgreSQL ownership/mode `0600` before its native
entrypoint drops privileges. Host permissions/content remain unchanged. Production TLS
validation, trust and IdP/browser behavior are unchanged.

An actual pinned-image Linux UID test confirms that PostgreSQL cannot read either
original source file, then can read both privately staged copies. Loading the original
helper command in memory reproduces **one expected failing assertion**, zero errors or
skips; the fixed helper passes all **six** focused controls. No source mutation was used
to manufacture the negative.

A separate [initial OIDC/PostgreSQL job](https://github.com/SoupTeam/soup-wall/actions/runs/38683493629/job/116253029227?pr=120)
passed database startup, TLS, migrations, session and restart checks, then timed out in
`idp-password-callback-analyst`. That failure is retained independently; it is not evidence
of the private-certificate defect. Hosted checks on the final revision and review remain
required; there is no test skip, weakened assertion or task-closure claim here.

## Repeated real-process outcomes

| Observation | SQLite | PostgreSQL |
| --- | --- | --- |
| Driver checks | 74 passed, zero failed | 88 passed, zero failed |
| Nested receiver checks | 9 passed | 9 passed |
| Current encrypted backup | 0.031033 s | 2.795178 s |
| Verified current restore | 0.075106 s | 2.045163 s |
| Valid restore → two live hooks and matching new signed acknowledgements | 3.965307 s | 4.854986 s |
| Webhook outage/lost-ack/restart recovery | 59.447910 s | 60.180652 s |
| Complete fixture including negatives/cleanup | 77.077360 s | 103.750938 s |
| Private files/processes/container cleanup | complete | complete |

Both runs retain the original predeclared 120-second restore-to-hook/ack and separate
180-second webhook bounds. Both repeat complete row/sequence/DDL equality, retained/
revoked credentials, two actual Agents, current higher-sequence deployment, restart,
stale-backup rejection and return to online behavior. The PostgreSQL driver additionally
repeats source-alias, populated-target and archive/schema/inventory refusal controls;
SQLite target/archive refusals are covered by the separate native SQLite/age Python
regressions, not claimed as additional integrated-driver cases. All owned private trees
and processes/container resources were removed. No customer/default DB.

**Python repeat:** 506 run, 481 passed, 25 documented platform/optional skips; the new
Linux UID regression was explicitly enabled and passed. Native Rust sources/binaries
did not change: the original 1,046-test workspace, formatting and Clippy evidence applies.
The newly changed helper is additionally covered by both full real-process repeats.

Runtime input SHA-256:
`33bb7d4d63b809c259c79b959120b6cab56ff89b60fbe83345061011837c25cf`.
Exact native binary/config/trust hashes remain recorded in each outcome.

[SQLite outcome](CONSOLE_RECOVERY_2026-10-15.followup.sqlite.json),
[PostgreSQL outcome](CONSOLE_RECOVERY_2026-10-15.followup.postgres.json),
[sanitized raw archive](CONSOLE_RECOVERY_2026-10-15.followup.raw.tar.gz),
[verified member digests and original diagnostic links](CONSOLE_RECOVERY_2026-10-15.followup.raw-manifest.json).
All eight members were independently read back and verified. Archive SHA-256:
`c384980c75994a317eee61c5bab70536f9a243f6705ad046f93b3b9ec1c1b4b4`.

The existing bounded webhook seam remains explicit: native claim/sign/send/fenced-finish
through a test-only local HMAC adapter to the existing authenticated durable receiver.
`production_external_https_delivery_verified` remains **false**. This does not establish
production external HTTPS delivery, exactly-once network delivery, host acceptance,
release readiness or automatic stale-sequence reconciliation. Independent review must
accept these limits before SOU-49 closure. Hosted CI status is linked in the PR.
