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

## Focused CI result on PostgreSQL 16 (workflow_dispatch, no full matrix)

`managed-group-rollout.yml`, run `41712822310`, exact source `10965ca204f40e72732b2cfee90a1e534b143808`, **passed**: the SQLite
regressions including `managed_cohort_confirmation`; the existing PostgreSQL fault/concurrency controls; the new step
`Run cohort preview and guarded start controls over HTTP on PostgreSQL`; and both existing real-Agent demos with encrypted
SQLite and PostgreSQL recovery (which exercise the updated recovery inventory). The earlier run `41711567465` (source
`fd5d58ed`) failed only the SQLite recovery step for the inventory reason above and is kept, not relabelled. The local
PostgreSQL 14 caveat below therefore no longer limits the PostgreSQL claim for this source. The Playwright suite and
`console-rollout-acceptance.py` (Linux, `agent-fleet.yml`) were not dispatched: the former passed locally, the latter is
still unrun. This is not a full Ready CI, CodeQL or admission result. Later commits that change only this ledger are not
re-qualified.

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

## Review correction: resolved signing identity (November 4)

Review 5765415019 at source `d4019bbc` reproduced an old preview being accepted
after a default signer rotation. Requested `issuer_key_id: null` and
`signer_available: true` were insufficient to freeze the signing identity.

The authoritative preview now includes `resolved_signer.issuer_key_id` and
`resolved_signer.public_key_sha256` (SHA-256 of raw Ed25519 public-key bytes),
covered by `snapshot_sha256` and shown in the Console confirmation. SQLite and
PostgreSQL derive the start snapshot from the actual `ManagedIssuer` reference
used for issuance inside their existing transaction/lease. They do not re-read
an unrelated environment signer to validate a different signing instance.
No new migration or seed/publication surface is introduced. Previously unconsumed
confirmations without the new binding fail stale; consumed confirmations retain
their reconciliation behavior, including after signer rotation/removal.

The shared real-TCP fixture now covers default ID rotation, same-ID key-material
rotation, explicit default selection, and a named non-default key rotation after
server shutdown and storage reopen. Each old confirmation returns 409
`confirmation_stale` with no change to deployments, revisions, sequences or
rollouts and no confirmation consumption. A fresh preview can start using the
rotated identity; restoring the exact old signer also proves the refused
confirmation was not consumed. A consumed confirmation replays its original
rollout after restart without a signing seed. A direct store witness passes a
different actual issuer while the environment still matches the preview and
requires the same zero-write refusal, covering a capture/recheck race.

Local macOS checks use read-only source, scratch-only writes and loopback-only
Seatbelt. All 357 proxy tests passed (10 explicit environment-dependent ignores);
all-target proxy Clippy with `-D warnings` passed. Full-suite snapshot
`8ea9c5b24957e51a42b3a91a92f3356890edaee86ef5e1c0c00ad8d0894749fc`, log
`07772959e4f115747cbcf40fbd4ce66823c16226ec2136af2fdfde963c6fa227`.
Clippy log `ceeb9751d8e4973de28a50d91dfd58fba8851db26a8e7659d388a0a94eec7e92`.
The final subsequent test-only extension additionally checks fresh rotated-key
preview/start; its focused rerun is recorded separately.

The updated browser assertion checks the visible actual key ID and fingerprint.
Local browser execution is **not claimed**: Chrome could not create its process
singleton socket under the scratch-only enclosure; the required runner rejected
the skip. No host browser security or user-profile permissions were relaxed.
PostgreSQL 16 and Linux browser evidence for the review correction are recorded
below; the earlier November 3 run does not cover these new signer controls.

Final focused rerun (including fresh rotated-key previews): passed SQLite HTTP
controls, formatting, strict all-target Clippy, generated-workflow consistency
and 425 Markdown files / 1354 local links. Snapshot
`f989aa83cb8a32d64115dd774530d8e262579935040fde9703f1ef6c4ee16dff`, log
`875c5476554b7fbd5a34deb6e2e12d89fa953dcb2b30bc51d481ecb512a25f96`.

### Corrected-source native qualification

Exact implementation source: `54e9663ed8f7115356f6bf3d338ba5acef7d571a`.

- [Managed group rollout run 41801008661](https://github.com/SoupTeam/soup-wall/actions/runs/41801008661):
  **passed**, including the updated real-HTTP confirmation/rotation fixture on
  SQLite and PostgreSQL 16, existing PostgreSQL fault/concurrency controls, and
  both four-real-Agent encrypted recovery demos. The two retained demo reports
  were independently checked: each has `passed: true` and all 31 checks true.
  Artifact `13307512745`, two unique safe CRC-valid members, ZIP SHA-256
  `fd9a55c8b563588184a318618d6d8c08264cadf49e89a41387ffe18ec53a22ed`.
  Complete job log SHA-256
  `4f9009e0c9d9ee413c5c1c5d7b334b439f8d97a5e2df81088697d632df4d9a61`.
- [Agent fleet run 41801017361](https://github.com/SoupTeam/soup-wall/actions/runs/41801017361):
  **passed**, including all 17 rollout-panel Playwright regressions with the new
  visible key-ID/fingerprint assertion, real SQLite/PostgreSQL Console/Agent
  witnesses, and the real HTTPS rollout scenario. Artifact `13308181049`, 56
  unique safe CRC-valid members, ZIP SHA-256
  `1453dbfe8810daf05c89ede8c76812e024551ebc9b89716620662b0c89b6bcf3`.
  Rollout report SHA-256
  `b380ea9b96f413bdad47905073cf9028b2fae2d9a52b4f9d1498b4cf3cc215c7`;
  complete job log SHA-256
  `1ca31707db0f7a173cd5c2b788be1c193fdcb169bf1b32aca4c42aff57837bbb`.

Two separate disposable mutation controls failed as required: reloading the
environment instead of checking the actual issuer allowed the wrong captured
issuer through; omitting public-key material from the snapshot reproduced
HTTP 201 instead of 409 on same-ID key rotation. Neither mutation was published.
Mutation log hashes, respectively:
`c61feefc3c8ebffa06ea2fc50e58d64334d63fabf14a872a1a08d8400a094a8b`,
`afb9d16ba61cc2f04b30054036b738ed7e4b91773abc81b618c617378c6cacc4`.

This subsequent ledger-only commit changes no implementation or test bytes.
These focused runs do not replace maintainer-owned final Ready CI, all CodeQL
analyses, exact-current-base candidate admission, re-review or merge. The
migration-29 collision with #350 remains an integration note, not a new migration.
