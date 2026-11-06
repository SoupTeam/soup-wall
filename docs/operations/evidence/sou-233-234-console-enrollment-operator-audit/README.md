# SOU-233 and SOU-234 acceptance

Accepted base: `8003fac2d271156e2229c8c15c6eddb98ee2da8e`.

## SOU-233 — Enrollment to actual policy application

The browser witness provisions an owned Agent credential, installs the exact
bytes via the displayed command, and runs the displayed preview and apply
commands with an installed binary and working directory outside the checkout.
It uses independently derived issuer trust and an owned HTTPS CA. It checks
wrong issuer and CA refusals, corrected setup, the distinction between fetched
and applied, the authenticated application record and a real hook verdict.
It also exercises rotation without restart, an actual lost committed response,
role denial, a rejected candidate with the old applied policy still visible,
and guarded disconnect.

## SOU-234 — Operator audit

The same Console exercises separate denied, failed and committed facts, exact
actor and target attribution, stable pagination, tenant isolation, bounded
retention and restart. A fixture trigger suppresses the audit insert to verify
that the state mutation rolls back. Concurrent requests and exact receipt
replays verify one committed fact per storage change. The schema upgrade
control recreates the preceding schema in the owned fixture and verifies that
the existing records survive the upgrade. The encrypted recovery fixture
checks the accepted schema and preserves audit rows and sequence state.

## Reproduction and evidence scope

- The existing `agent-fleet.yml` workflow runs the enrollment and operator
  audit witness on SQLite and TLS PostgreSQL, with an actual Linux Agent.
- The existing `console-recovery.yml` workflow exercises the encrypted
  backup and restore contract on both stores.
- Each enrollment report records its source commit, clean-tree status, build
  and configuration digests, source file hashes and individual check outcomes.
  The workflow reports are the acceptance evidence. Local browser and HTTP
  controls do not establish installed Linux behavior.
- Retain failed attempt reports with their source attribution. Never include
  fixture credentials, raw policy documents, database URLs, browser state,
  or unsanitized Console logs in evidence.

## Local qualification

- Workspace Rust tests completed with 2,044 passed and 16 explicit ignores.
  The first run stopped at an outdated assertion for the rotation route in
  the rendered dashboard. The final run includes the updated assertion.
- Real Console HTTP controls passed 15/15 on SQLite and 15/15 on TLS
  PostgreSQL 16.15 on macOS. The controls include audit-write suppression
  for enrollment and policy deployments, concurrent rotation and deployment,
  audit retention, scope, and persistence after restart. The token-shaped
  ID control failed before redacting the Console token prefix and passed
  on both stores after the fix.
- Final browser/recovery controls passed 51 tests with one Linux GNU
  installer control skipped on macOS. Release archive controls passed
  22/22, Console endpoint regressions 22/22, and workspace/all-target
  Clippy with `-D warnings` and formatting passed.
- An unchanged Agent lifecycle test failed once in a final parallel run.
  It passed in isolation and the complete workspace retry passed on the
  same final source. All failed development outcomes and private log digests
  are retained in [local qualification](local-qualification.json).
- The broader macOS browser sweep hit `Download.path: canceled` in the
  existing Agent history export test. The same test reproduced that result
  on the exact accepted base. The operator audit export has its own check.

Operator instructions: [installed connection](../../INSTALLED_MANAGED_CONSOLE.md)
and [operator audit](../../CONSOLE_OPERATOR_AUDIT.md).

## Linux results

Final clean runtime: `64ad83dbac02fb1efac0012bfe0d33a7d62a1896`.

| Final source-bound qualification | SQLite | PostgreSQL |
| --- | --- | --- |
| Installed connection and operator audit | 62/62 | 64/64 |
| Encrypted recovery | 74/74 | 88/88 |

The [final browser and real Agent run](https://github.com/SoupTeam/soup-wall/actions/runs/42077685062)
passed the complete fleet component, including the browser regressions and
both installed enrollment journeys. The [final encrypted recovery run](https://github.com/SoupTeam/soup-wall/actions/runs/42077691691)
passed on the same source. Every check in all four reports passed. Each report
declares a clean source, whose 271 enrollment or 343 recovery input hashes
were independently verified through `git show` at that commit. Both artifact
digests and all ZIP CRCs matched. The final reports are retained under
[final enrollment](final-enrollment/run.json) and
[final recovery](final-recovery/run.json). The earlier attempts below retain
their original source attribution.

The [encrypted recovery run](https://github.com/SoupTeam/soup-wall/actions/runs/42070311455)
passed 74 SQLite and 88 PostgreSQL controls on clean runtime
`29bf830a7fbb2c4da067bf484b338bb12a7eaefc`. All 343 input hashes in each
report were verified against Git. The artifact SHA-256 and ZIP CRC also
matched. Retained reports and verification are in [recovery](recovery/run.json).

The [first enrollment attempt](https://github.com/SoupTeam/soup-wall/actions/runs/42070305185)
stopped before connection setup because the fixture selected its private file
writer from the wrong helper module. Both failed reports are retained under
[attempt-1](attempt-1/run.json), with the original runtime and verified input
hashes. The corrected driver imports the existing credential writer and its
regression checks private atomic replacement before the next Linux run.

The [second enrollment attempt](https://github.com/SoupTeam/soup-wall/actions/runs/42073386456)
passed all 61 SQLite controls. The PostgreSQL attempt reached a committed
rotation whose deliberately lost response left the page in its sending state.
Both original reports are retained under [attempt-2](attempt-2/run.json).
A separate browser regression reproduced an indefinitely stalled response
body and failed before the fix. Enrollment requests now settle after a
20-second deadline and reconcile the same operation without an automatic
resend. The regression verifies that the explicit retry is byte-identical.
