# Encrypted current-state Console recovery — 2026-10-15

SOU-49, Phase 6 internal candidate. Runtime source:
`82d41b0bf2ac90b20df42812b4c459981f32bded`, based on accepted main
`4f428e4b983111e5b2480e40d658628e3d198fe7`. Both real-process runs started
with a clean worktree and retained identical complete runtime-input and selected-binary
hashes through cleanup. The first evidence-only delivery `898847c` added a public-CLI regression without changing
runtime inputs. A later [CI portability repair and repeated proof](CONSOLE_RECOVERY_2026-10-15.followup.md)
is recorded separately; original outcomes below are unchanged. Hosted CI and independent
review remain gates.

[Operator commands and reproduction](../CONSOLE_RECOVERY.md),
[SQLite outcome](CONSOLE_RECOVERY_2026-10-15.sqlite.json),
[PostgreSQL outcome](CONSOLE_RECOVERY_2026-10-15.postgres.json).

## Actual outcomes

| Check | SQLite | PostgreSQL |
| --- | --- | --- |
| Driver assertions | 74 passed, 0 failed | 88 passed, 0 failed |
| Nested restored receiver assertions | 9 passed | 9 passed |
| Quiesced current backup | 0.030838 s | 1.747678 s |
| Verified current restore | 0.073585 s | 1.816994 s |
| Valid restore start → two new signed acknowledgements and live hooks | 3.870411 s | 4.200256 s |
| Outbox outage/lost-ack/restart/retry recovery | 60.312468 s | 60.427507 s |
| Entire fixture including negatives and cleanup | 77.497722 s | 99.389003 s |
| Private fixture cleanup | complete | complete, owned container removed |

The 120-second restore-to-live-hook/ack objective was declared before execution and
excludes fixture setup, backup creation and isolated negative controls. The separate
outbox bound was 180 seconds. These small owned-fixture observations are not production
RTO promises or scale measurements. Driver counts include repeated state observations;
the nine nested receiver checks are reported separately, not summed as independent cases.

Each backend used two tenants and two actual Agent processes, explicit independently
pinned native trust files, retained and revoked service/enrollment credentials, approved
policies and populated security/webhook state. All native rows, sequence values and
logical schema were privately compared before runtime startup. No counts-only success.

Live hooks observed **deny (sequence 1) → defer (2) → restored defer (2) → newly signed
deny (3)**, with exact matching authenticated Console acknowledgements. SQLite reopen,
PostgreSQL container restart, Console restart and an Agent durable-cache restart retained
state. Returning from the stale target and the webhook outage required both Agents to
reconnect with actual transport state `online`; cached policy alone could not pass.

The stale archive contained the earlier deployment history. Its newly issued sequence 2
was rejected by each Agent already running sequence 3; hook denial and durable policy
remained unchanged. The negative explicitly records `recovery_complete: false` and
operator guidance to stop the stale Console and recover a current snapshot. No counter
reset, acknowledgement fabrication, trust-root change, reconciliation or new epoch.

Actual PostgreSQL refusals covered a differently spelled URL resolving to the source's
cluster/database identity, an independently populated target, damaged ciphertext, the
wrong identity, and correctly re-encrypted archives with incompatible schema or inventory.
Each verified original source equality plus actual fresh-target identity/emptiness, or
preserved sentinel rows/DDL for the intentionally populated target.

The [native schema provenance](CONSOLE_RECOVERY_2026-10-15.schema.json) records a fresh
explicitly migrated schema-26 PostgreSQL fixture and genuine DDL negatives: missing
immutability trigger, CHECK constraint or index; added function/view; custom `pgx_*`
namespace; and nonempty target. The versioned inventory covers 44 PostgreSQL tables,
312 columns, 190 constraints, 100 indexes, four immutable-event triggers, three functions
and seven sequences. The SQLite accepted managed fixture has 43 native tables and exact
native schema objects. Unknown later schemas, including future fleet tables, are refused.

## Verification and retained evidence

- Rust workspace: **1,046 passed, 0 failed, nine ignored records** across 53 targets.
  Eight were existing platform/opt-in records. The new outbox fixture is intentionally
  opt-in in ordinary cargo test and was explicitly executed three times per backend
  against the real restored database, with actual receiver witnesses.
- Native seed/probe helper: all ten controls passed, included in the workspace total.
- Python scripts: **505 run, 480 passed, 25 skipped**. Skips: 15 selected Linux TLS
  runtime checks, five optional Playwright checks and five native Windows checks.
  Core encrypted-recovery controls were not skipped. Fourteen core/public-CLI controls
  and fifteen driver safety/evidence controls passed.
- Benchmark helpers: **44 run, 28 passed, 16 individual skips**, plus two class-level
  skip records (unittest summary reports 18). No optional AgentDojo/model installation.
- Formatting, warnings-denied workspace/all-target Clippy and documentation links passed.
  The initial generic Python command lacked existing SAML-test dependency `urllib3`;
  its original error log is retained. The pinned fixture environment resolved it without
  changing that test; the complete 505-test run above passed.

The actual public backup/restore CLI also completed a separate native-age SQLite
roundtrip with complete state equality, preserved revocation, sequence continuity,
unchanged source, structured safe receipts, private permissions and scratch cleanup.

Runtime input digest on both backends:
`438f16412f9c60313780dc144b5d27e65bc9b02ed35058f171e84e0019aa48dc`.
Individual native source/assets, binary, Agent trust/configuration and Console
configuration hashes are in the outcomes. Operator settings were retained separately
and checked byte-for-byte, alongside the live issuer public-key identity.

[Raw sanitized archive](CONSOLE_RECOVERY_2026-10-15.raw.tar.gz),
[member sizes/digests and runtime configuration](CONSOLE_RECOVERY_2026-10-15.raw-manifest.json).
All 14 member byte counts and SHA-256 values were independently checked after packing.
Archive SHA-256:
`5d71d31ccdd1ca804befd3225cbab1414fe38c1ada676f9af96bbad8706f14a4`.
No credential values, decryption identities, plaintext database dumps or private row
snapshots are included. The two initial diagnostic results remain immutable `incomplete`
records because explicit private retention was enabled; their private trees and the
schema-generator private artifacts were subsequently removed. Final runs used default
complete cleanup and retained no private fixture resources.

macOS 26.3.1 arm64; Python 3.14.3; native age 1.3.2; PostgreSQL client 16.15.
The real PostgreSQL run uses the existing pinned image from the hashed Keycloak fixture;
the independent schema reference uses its separately recorded pinned PostgreSQL 16.13
image. Full Rust/tool/Python dependency versions are in the raw context.

## Controlled deployment limits

The production destination validator/resolver and SSRF protections remain unchanged.
Outbox testing uses native claim/sign/send/fenced-finish code **only in the unit-test
binary**, through an explicit loopback HMAC adapter to the existing authenticated durable
Alertmanager receiver. It preserves original delivery/event identity and waits native
retry backoff. The initial seeded +1800-second pending time is advanced as an explicit
fixture clock control; retry and lease metadata are labelled synthetic stopped-source state.

Three real native attempts produced HTTP 503 (receiver unavailable), 503 (receiver
committed but acknowledgement was withheld), then 200 after receiver restart. The outbox
ended delivered at total attempt count four, including one initial synthetic attempt.
Receiver storage retained one durable effect and one deduplicated retry. Source Console
remained stopped throughout recovered delivery; all original source rows/sequences
remained unchanged. This is neither exactly-once network delivery nor a shared external
transaction. `production_external_https_delivery_verified` remains **false**.

All runtime traffic was owned numeric loopback; PostgreSQL used its explicit local
`sslmode=disable` exception. Backup encryption does not establish remote TLS acceptance.
This evidence does not cover customer/default databases, remote Agent transport, external
IdP login, automatic point-in-time reconciliation, future fleet schema, Windows ACLs,
production external HTTPS webhook delivery or release publication. No migration or
policy/acknowledgement/Agent/identity protocol was changed. Independent review must
accept the stated local webhook seam and the bounded recovery objective before closure.
