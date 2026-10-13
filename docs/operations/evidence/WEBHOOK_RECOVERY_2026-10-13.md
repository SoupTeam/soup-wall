# Webhook ownership and recovery — 2026-10-13

SOU-33 / Phase 6 bounded webhook reliability increment. Local acceptance passed;
review, remote CI and merge remain separate gates. This does not close the full
Phase 6 deployment acceptance or SOU-17 constrained-executor acceptance.

## Exact source and configuration

- Tested clean source: `108511a88ba7a7d047ff5568b4676123424dc507`.
- Current-main base: `b6075bd6698fe5cbfe65fffb29803749f3beb670` (accepted checkpoint
  `9cc2a304ce96bc79489b33e9d6397e974b75b3e2` is an ancestor).
- Cargo.lock SHA-256: `b47634e7508864daa1df5826433f4cc31d967b013e5719dd09f3ab453f38618a`; no dependencies added.
- macOS/Darwin 25.3.0 arm64; rustc/Cargo 1.99.0; Python 3.14.3.
- Real PostgreSQL 18.3 in a fresh disposable loopback cluster. CI targets its
  existing PostgreSQL 16 service; the PR records that independent result.
- Locked/offline Cargo; debug information and incremental builds disabled for
  this local run. No model, paid receiver, customer data or production key used.
- Subsequent evidence-only commits do not change the tested executable sources.

[Machine-readable results and independent receiver receipts](WEBHOOK_RECOVERY_2026-10-13.json)
include exact commands, exit codes, timings and log hashes. Reproduction commands
are in the [staging drill](../STAGING_DRILLS.md#webhook-ownership-and-receiver-recovery).

## Reproduced defect and resulting behavior

On the unmodified base implementation, both SQLite and PostgreSQL reproduce:
claim A → expire its lease → claim B → B succeeds → A reports a delayed failure.
The stored row changes **Delivered → Pending**, retains attempt count 2, and
records HTTP 503. The regression assertions correctly fail in both stores
(Cargo exit 101, zero passed/two failed). The only overlay is the retained
[test module](WEBHOOK_RECOVERY_2026-10-13.baseline.rs.txt); see the
[sanitized failing output](WEBHOOK_RECOVERY_2026-10-13.baseline.log.txt).

Completion now atomically requires the exact claimed attempt, lease, live
`in_flight` state and unexpired ownership. The same races pass on the candidate;
late success, late failure and completion replay leave newer state unchanged.
SQLite uses immediate claim transactions and PostgreSQL uses its database clock
with row locking. Crashes count toward the eight-attempt limit. Deactivation
prevents new attempts without pretending already received bytes can be recalled.

No schema version or columns change. Existing populated SQLite startup and
PostgreSQL migration reruns preserve delivered/live rows and ownership; a fresh
worker recovers the same event/delivery IDs after expiry. Request deadlines,
URL-free bounded errors, public address pinning and redirect refusal are covered.

## Verification results

| Check | Observed result |
| --- | --- |
| Fast `--lib webhook_` tests | 16 passed, 0 failed; 3 opt-in tests ignored here |
| Explicit PostgreSQL ownership/recovery suite | Passed; both stale-result directions, attempt/lease fences, backoff, crash exhaustion, deactivation, migrations and independent claims |
| Explicit receiver process-recovery demo | Passed, 43406 ms; real retry and lease clocks |
| Existing PostgreSQL control-plane compatibility test | Passed |
| Workspace Rust tests | 944 passed, 0 failed, 8 ignored in normal run |
| `cargo fmt --all -- --check` | Passed |
| Workspace/all-targets Clippy with `-D warnings` | Passed |
| `scripts/tests` Python suite | 362 run, 5 skipped, no failures |
| `scripts/benchmarks` Python suite | 44 run, 18 skipped, no failures |
| Documentation links | Passed; evidence links checked again after adding this report |

The normal Rust run ignores the live local model, Redis, PostgreSQL control-plane,
PostgreSQL webhook, receiver parent/child helper, real OIDC and real SAML tests.
Both PostgreSQL tests and the receiver parent were explicitly executed; its child
helper ran as real subprocesses. The remaining external model/Redis/IdP checks
are outside this increment. Python skips cover native Windows/DPAPI and explicitly
selected AgentDojo/native runtime environments; they are not counted as passes.

## Independent receiver evidence

Seven durable receipts, six authenticated requests, three unique applied fixture
effects, two recognized duplicate requests and one rejected tampered body:

| Scenario | Requests / final sender state |
| --- | --- |
| Useful delivery | 1 signed request; Delivered at attempt 1 |
| HTTP failure and retry | 503 then 200; Delivered at attempt 2 |
| Sender interrupted after receiver success | Receiver persists 200 receipt; child is killed before completion; new child reopens DB, waits lease expiry, repeats same event; Delivered at attempt 2 |
| Changed unsigned delivery header | Authentic body replay is deduplicated; no additional effect |
| Tampered body | Signature invalid, HTTP 401, no effect |

Retries retain identical event/delivery IDs and payload hashes. Receipt records
are independent of the sender database and synced before HTTP responses. The
receiver verifies the MAC independently with the registered secret and dedups
signed tenant/event IDs, not the unsigned delivery header. The receiver remains
running: this demonstrates sender recovery, **not receiver restart durability**.
The test uses the production claim/finish and request/signature functions through
a private test-only loopback seam. Production HTTPS/DNS/TLS restrictions remain;
no insecure runtime option was added. Public HTTPS delivery is still an operator
acceptance step.

## Development failures retained honestly

A first demo run failed when a concurrent historical build replaced the shared
Cargo test executable during the lease wait. The parent detected that the resumed
child had not completed the delivery. The fixture now snapshots its executable
and requires an explicit completion witness; the final exact-source demo passes.
The real PostgreSQL run also caught ambiguous CASE timestamp parameter types,
which were fixed with explicit BIGINT casts. A macOS socket can time out instead
of refusing immediately; that regression now accepts either bounded sanitized
failure category. Stable Clippy's fixed-size chunk requirement was corrected.
These failures were repaired before the final results above; no failed run was
reported as successful receiver evidence.

## Baseline reproduction and upgrade requirements

The retained baseline overlay only works with the pinned pre-fix source. Extract
that revision to a fresh directory, copy the overlay to
`crates/proxy/src/tenant_store/sou33_baseline_regression.rs`, then append
`#[cfg(test)] mod sou33_baseline_regression;` to `tenant_store.rs`. Provide a fresh
disposable PostgreSQL database named `sou33_baseline` on `127.0.0.1:62293` (the
fixture deliberately validates that exact local endpoint). Set
`SOU33_BASELINE_POSTGRES_URL` to that database with `sslmode=disable` and run:

```sh
cargo test --locked -p llm-firewall --lib sou33_baseline_regression -- --nocapture
```

Expected: exit 101 with the two Delivered-versus-Pending assertion failures.
Do not reuse an outbox from a failed run, use production data, or run the overlay
against the repaired API. Use a separate target directory when comparing builds;
the current receiver demo additionally pins its child executable.

Stop all old worker binaries before upgrading: their unfenced completion logic
can still corrupt delivery state in a mixed-version rollout. Keep signing keys,
attempt counts and receiver deduplication records. See the
[operator notes](../PRODUCTION_RUNBOOK.md#policy-webhook-delivery-and-recovery)
for bounded at-least-once semantics, terminal states, deactivation and rollback.
