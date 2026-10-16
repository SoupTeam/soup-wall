# SOU-47 acceptance and review audit

This audit covers PR #119 after `7ea7da0`, including the additional manual rollback ownership repair. It records implementation evidence; it does not substitute for reviewer approval.

## Review findings

All human review threads were checked, including outdated but unresolved GitHub threads. The latest review targets `2ab6977`, not the subsequent atomic implementation.

| Finding | Current behavior and regression coverage |
| --- | --- |
| Same-name/different-digest candidate | Full inventory validation rejects collisions before issuance; HTTP collision regression |
| Rollback reported successful before ACK | Persisted baseline sequences remain pending until exact applied ACKs; manual and automatic rollback regressions |
| Paused/rolling-back plan replaced | Both states retain ownership; conflicting-start and deletion regressions |
| Superseded canary opens standard wave | Latest sequence/revision/digest checked before promotion; superseded-canary regression |
| Missing signer manufactures a zero key | No fallback signer; issuer-unavailable regression |
| Partial standard wave allocates duplicates | Entire transition is transactional; injected second-worker failure, reopen and competing-handle retry |
| Baseline-free pilot counted restored | Explicit unresolved attribution; baseline-free pilot regressions |
| Unapproved second pilot leaves orphan | Whole inventory preflight and transactional start; approval and injected second-pilot failure regressions |
| Baseline-free standard worker omitted | Candidate cohort determined independently of free-text reason; manual standard-wave regression |
| Partial pilot start hangs after restart | Initial revision writes, plan and all deployments commit together; second-pilot failure/reopen/retry on both stores |
| Populated group schema breaks recovery | Explicit migration 27 and strict updated native inventory; populated migration controls and real encrypted recovery |
| Additional audit: old manual rollback overwrites newer ownership | Preflight refuses superseded individual deployments and another active plan's frozen inventory, including not-yet-issued standard Agents; shared regression first reproduced the defect before repair |

The shared fault fixture also aborts revision insertion, plan insertion and plan update. Reopening after each failed start finds no rollout or extra deployment sequence; removing the failure allows one complete pilot wave. Both SQLite and PostgreSQL execute these same controls.

## Original acceptance requirements

| Requirement | Evidence |
| --- | --- |
| Frozen tenant/inventory/approved policy/baseline | Start preflight, immutable revision digest checks and persisted initial sequences; collision, approval and tenant authorization regressions |
| Durable/idempotent orchestration and ownership | SQLite writer transaction; PostgreSQL exclusive tenant lease; shared fault/restart/concurrency controls, including one-connection PostgreSQL pool |
| Exact bounded canary gate | Authenticated existing ACK path; wrong/stale/wrong-Agent live controls; timely/late ACK and deadline regressions |
| Confirmed higher-sequence baseline rollback | Manual/automatic live hook behavior; unresolved baseline, rejection, supersession, identical-baseline restoration and late rollback ACK controls |
| Consistent authorized status | Snapshot-based expected/latest sequences, ACK/deadline and per-Agent state; all group writes require Owner; Viewer/Operator and Agent credential negative tests |
| Four real Agents and PostgreSQL | Both retained `managed-policy-group-rollout-{sqlite,postgres}-atomic-2026-10-15.json` reports include source/config/binary identities, 31 live checks, encrypted recovery, restart/retry and cleanup |

## Work inventory checked

Linear has nine issues assigned to Nariman Abdukarimov: SOU-8, SOU-10, SOU-15, SOU-24, SOU-40, SOU-44, SOU-45 and SOU-46 are Done; SOU-47 remains In Progress pending acceptance. All earlier authored PRs are merged; #119 is the sole open authored PR. No open PR currently requests his review. Telegram's earlier request to review #122 was fulfilled: his approval is recorded and #122 is merged.

The latest Telegram request concerning #119 repeats the partial-pilot-start finding on `2ab6977`. No later technical finding was present at this audit. Nothing was sent to Telegram and no reviewer thread was marked resolved on the reviewer's behalf.

## Verification and remaining acceptance

The complete proxy all-target suite passed 331 tests with 9 expected fixture skips. The PostgreSQL shared fixture was separately executed against a disposable native PostgreSQL 17 database. All 31 native-age recovery tests passed without skips; Clippy with `-D warnings`, formatting and diff checks passed. The live reports and hosted CI identify the exact source they tested; consult those identities rather than assuming an earlier green head covers a later change.

SOU-47 remains open until independent review accepts the current implementation. Entirely offline fleets require Owner advance to process expired deadlines. Older schema-26 archives require the matching recovery tool before normal migration. Evidence is controlled local-process validation, not production multi-host certification or publication authorization. Periodic model monitoring remains disabled.
