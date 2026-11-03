# SOU-220 evidence: authoritative cohort preview and guarded group start

Base: `2a5bf6771c63c6ccf2c55d07dede512a72f26481` (accepted `main`). Scope: the existing group rollout API/store and
the Console rollout panel. Individual deployment issuance (SOU-219), heartbeats, enrollment and Agent enforcement are not
touched. This file records local runs by the author; it claims no CI, CodeQL or acceptance result. Final Ready CI, candidate
admission and merge are lead-owned.

## Local runs (macOS, PR head before this ledger commit)

| Command | Result |
| --- | --- |
| `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` | clean, 0 warnings |
| `cargo test -p llm-firewall` (all binaries, SQLite) | all passed, 0 failed |
| `cargo test -p llm-firewall --test managed_cohort_confirmation` | SQLite passed, PostgreSQL ignored (below) |
| same, `-- --include-ignored` with `SOUP_COHORT_TEST_POSTGRES_URL` | SQLite and PostgreSQL both passed |
| `cargo test -p llm-firewall --lib managed_confirmation` | 4 unit tests of the pure rules passed |
| `scripts/tests/test_console_rollout_browser.py` (Playwright 1.55.0 driving the installed Google Chrome) | 17/17 passed, including 5 new controls |
| the agent-history and fleet-triage browser suites, same runner | passed |
| `scripts/tests/test_console_enrollment_browser.py`, same runner | 2 subtests fail (`displayed_installer ... refuses_unsafe_targets`, exit 64 != 0); **identical on the unmodified base**, a Linux installer exercised on macOS; not caused by this change |
| `python3 scripts/ci_components.py --check`, `python3 scripts/check_docs.py` | clean |

## Console recovery inventory (found by the first focused CI run)

The first focused run (`41711567465`, source `fd5d58ed`) passed this PR's SQLite and PostgreSQL controls but failed the
existing step `Four real Agents with encrypted SQLite recovery`: the versioned recovery inventory
(`scripts/fixtures/console_recovery_inventory_v1.json`) is a strict allowlist of tables, DDL digests and PostgreSQL
migrations 1 through N, and `managed_group_start_confirmations` was not in it. Following the SOU-55 precedent, the next
commit adds the table to the SQLite and PostgreSQL inventory and raises the accepted schema version from 28 to 29 in
`console_recovery.py`, its acceptance driver, unit test and `CONSOLE_RECOVERY.md`. The fixture entries were generated from
live catalogs (SQLite's own DDL digest; the recovery tool's `logical_schema()` on a database migrated by this branch), and
the generator refuses to write unless every pre-existing entry is identical to the accepted fixture. The migration number
was also changed from 30 to 29 so this branch is self-consistent on `main`. **Integration note:** SOU-219 (PR #350)
independently takes migration 29 and the same inventory fields; whichever merges second must renumber to 30 and merge the
two fixture additions. The encrypted backup/restore demos have not been run locally (`age` is not installed); the
re-dispatched workflow is the evidence.

## Explicit skips and caveats

* **PostgreSQL 16 not observed by the author.** The local server was PostgreSQL 14.17. The existing migration contains the
  literal `841_337_611`, which only PostgreSQL 16 accepts; for the local PostgreSQL run that one literal was replaced in the
  working tree and reverted with `git checkout` each time. It is not in this PR. The CI step that produces the PostgreSQL 16
  result is `Run cohort preview and guarded start controls over HTTP on PostgreSQL` in `managed-group-rollout.yml`.
* `scripts/console-rollout-acceptance.py` (real Agents behind a TLS edge, Linux only) was updated for the new preview text but
  **not run** here; it runs in `agent-fleet.yml`.
* No full CI matrix was dispatched.

## Controls (`crates/proxy/tests/managed_cohort_confirmation.rs`, real TCP listener)

Deployments, rollouts, members, revisions, sequences and confirmations are counted with direct SQL; what an Agent receives is
read through `GET /agent/v1/policy`.

| Cause | Control |
| --- | --- |
| Preview is read-only | members, revisions, deployments, rollouts and max sequence identical before and after; the pilot receives nothing; only one confirmation row exists; a second preview replaces it and the older id is then invalid |
| Authoritative content | exact pilots/workers, the digest equals the stored group revision, baselines and sequences per Agent, five-minute expiry, blockers (unapproved/unknown revision, unacknowledged deployment) withhold the confirmation |
| Exact successful cohort | frozen pilots/workers equal the previewed ones; only the pilot wave is issued and delivered with the previewed digest; the confirmation is consumed |
| Lost response | three retries with the same confirmation return the same rollout (`replayed:true`), deployments and rollouts unchanged |
| Drift (8 causes) | member added, removed, pilot flag changed, Agent revoked, baseline changed, sequence advanced, another group's rollout claims an Agent, same-group rollout started: each is 409 `confirmation_stale` with deployments, rollouts, scope state and the unconsumed confirmation unchanged; a fresh preview then starts exactly its own cohort, or stays blocked where the cause blocks |
| Binding | other administrator, other tenant, forged tail, malformed and random ids, other revision, other signer: 409 `confirmation_invalid`; expiry forced in storage: 409 `confirmation_expired`; reuse for another revision and after another rollout replaced it: 409; reuse for its own revision returns only the original rollout |
| Authorization | viewer/operator 403, unknown 401, revoked Owner 401 at the middleware **and** refused inside the store; inactive tenant and missing group refused |
| Unavailable store | injected failure on the confirmation insert: preview fails, nothing recorded; injected failure on consumption: the whole start rolls back (no policy, rollout or revision), then the same confirmation starts after the fault is removed |
| Concurrency | 12 simultaneous starts with one confirmation: exactly one fresh, 11 replays, one pilot wave; two administrators racing for one group: one 201, one 409, one rollout |
| Restart | server aborted and storage reopened between preview and start, and between start and a retry: both succeed without a second issuance |
| Legacy | start without `confirmation_id`, including its documented idempotent repeat, is unchanged and has no `confirmation` object |

## Mutation checks run by the author

Each of these makes the suite fail: skipping the snapshot comparison, ignoring expiry, ignoring the administrator binding, and
skipping the in-transaction administrator recheck.

## Browser behavior

Real Console (this branch's binary, SQLite) driven in the built-in browser with synthetic data: the panel showed the server
preview (cohort, digest, baselines, sequences, snapshot); a member was added by API after the preview; confirming the old
preview showed "Nothing was issued", rollouts stayed 0 and deployments stayed 4, and the panel displayed a new preview that
included the new member; confirming that one froze exactly that cohort, issuing only the pilot (deployments 5, one rollout,
one consumed confirmation). The Playwright fixture suite adds: sends only the previewed confirmation, drift refusal then a second
preview with a single refused start, blocked preview with no confirm control, unavailable or mismatched preview never allows a
start, and a lost start response reconciles with no resubmission.

## Known limits

The bounded preview describes at most 500 Agents. A confirmation does not cover the signing key's trust in the Agent keyring.
The Console cannot detect a rollout that finished between preview and start except through the server's refusal. The legacy
unguarded start remains available by design; the guarantee exists only for callers that send the confirmation.
