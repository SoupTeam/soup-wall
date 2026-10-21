# SOU-83 requirements and review audit

## October 21 continuation

The October 20 matrix below is a historical evidence snapshot. PR #196 remains
the only delivery PR; SOU-83 remains In Progress. Main `8aa0482` is already
included. At starting head `6a8bc718`, current CI had 69 successful checks,
two failures and two expected skips. Required original filesystem acceptance
passed; Windows aggregate budgets passed. The failures were Windows lifecycle
recovery (`baseline daemon is not running before clearing journal`) and a
Keycloak SAML/Postgres browser logout timeout. Neither is established as an
original-create defect; SOU-103 source is unchanged by this continuation.

This continuation fixes a concrete create-only scheduling gap: native grant
reclamation could remove a cancelled call while its original producer still
ran cleanup, allowing a second writer to enter. An owned lease now spans the
logical call, detached reclaim/result work, original producer and blocking
anonymous staging worker. Two local regressions cover early logical removal
and an aborted async staging waiter. The result-inspection boundary also
rejects expired calls before preparing a stage.

New required upstream acceptance covers ephemeral worker SIGKILL, host EOF,
collector SIGKILL, zero fault publications, owned-process cleanup and fresh
create continuation. Signals use observed process start times plus pidfds.
The grader requires the signal identity and cleanup evidence, and six exact
successful publications. Existing cancellation/daemon-loss/replay/egress/
performance controls are retained. Successful-RPC latency samples exclude
bounded busy refusals while an earlier cancelled worker cleans up.

New Linux controlled relay tests pause completion at CreateInspected and
CreateStaged, inject cancellation/EOF, check no publication, reject spent IDs,
and complete a new create. They also check that policy activation cannot
overtake the held create boundary. Their synthetic stage producer and mock
native receipts are compile-time test seams; they do not qualify actual
upstream containment or a complete managed policy-epoch transition.

A separate actual native-router regression now changes the selected original
write policy from Allow to Ask/Deny between call and result, checks refusal
and single-use spending, restores Allow, proves old authority stays spent,
and completes a fresh exact-host call/result. This narrows the native epoch
verification gap; live signed managed deployment combined with the original
worker remains separate. The complete local native endpoint suite is now
151/151. Completion events that observe an expired/uncertain authority also
return a correlated no-commit error rather than silently removing the call.

Current continuation qualification is pending its own hosted Linux run.
Do not transfer `6a8bc718` or `2b7c7e28` evidence to the changed source.
Ask continuation, separately retained typed-resource evidence, full managed
epoch transitions, broader crash/race/adversarial-upstream injection and
actual upstream error injection remain full-task limitations. Private staging
cleanup after abrupt collector death is not an exhaustive crash-durability
claim. No merge, Done transition or review-ready claim is authorized by this
document.

Audit date: 2026-10-20. This is an evidence map, not task acceptance.
Baseline inspected: PR #196 `dcb048b871fa184612b4d09019f2e19d5ba8cd5e`,
including accepted main `d49efa5aec1d47a1471e4e67b343c85a8a392353`.
The additional acceptance controls in this change require their own CI; the
baseline's green checks do not qualify this change.

## Complete source inventory

- [SOU-83](https://linear.app/soup-wall/issue/SOU-83): complete description,
  Deliver 1–6, ownership and Done; all nine comments returned, no next page.
- Baubek Serikbay: `55e715c1-53ac-4266-b8af-2535826006d2` (production
  loader and installed path); `ddc170db-747f-4b41-8e03-9796fcacc3ff`
  (independent correction, new-main conflict, remaining task-wide evidence);
  `413083c1-8ca5-4a7c-adfc-b4dd8bc26de5` (preserve separate authority,
  current-source qualification); `d503b5d1-6049-4f3e-90a3-509e077594b4`
  (finite mutation fault gate, genuine receipt replay, continuation, Ask limit).
- Author's five Linear updates: `38c1aa92-6e9d-4b45-befb-538556c6ae6a`,
  `c989494b-7659-40b8-8fef-4ecc958edb17`,
  `4660a1ff-78f0-487a-8405-36448c331d97`,
  `f85f3b4b-22c0-4d2c-8c3c-f1be367f90bd`,
  `8ffc805f-e83e-4a22-b024-2a6d9e0a2f9d`. These record the earlier
  scaffold/staging-only/native-integrated sequence and outstanding work;
  their implementation claims were checked against code and independent CI.
- [Initial winux125 review](https://github.com/SoupTeam/soup-wall/pull/196#pullrequestreview-5583481180)
  and [inline P1](https://github.com/SoupTeam/soup-wall/pull/196#discussion_r4323681609),
  including [author response](https://github.com/SoupTeam/soup-wall/pull/196#discussion_r4324148456).
- All subsequent winux125 conversation/reviews:
  [3013fea recheck](https://github.com/SoupTeam/soup-wall/pull/196#issuecomment-6289750091),
  [8127558 merge resolution](https://github.com/SoupTeam/soup-wall/pull/196#issuecomment-6289844328),
  [P1 resolved, not full approval](https://github.com/SoupTeam/soup-wall/pull/196#pullrequestreview-5584507491),
  [finite acceptance gate](https://github.com/SoupTeam/soup-wall/pull/196#issuecomment-6290443329),
  [97db581 recheck / separate Windows diagnosis](https://github.com/SoupTeam/soup-wall/pull/196#issuecomment-6292905932).
- All six submitted reviews were read: three empty CodeQL COMMENTED reviews,
  winux125 CHANGES_REQUESTED, author's empty COMMENTED, winux125 COMMENTED.
  All four inline threads were read, including replies and resolution metadata:
  three obsolete CodeQL workflow threads and the P1 thread are resolved;
  zero unresolved inline threads. Aggregate review decision still
  CHANGES_REQUESTED. Resolving a thread is not approving the PR.
- All seven surviving PR commits were inspected: `3013fea` (integrated loader,
  original result and implementation), `8127558` (main union authority merge),
  `61959d0` (main plus fault controls), `b9e134c`, `5f2c50b`, `97db581`
  (correct native replay contract and original host ID), `dcb048b` (current
  main merge and truthful scope). Earlier rewritten scaffold commits remain
  historical discussion only; they are not additional current PR commits.

## Requirement matrix

Confirmed means the indicated boundary has implementation and executable
evidence. Partial means the named evidence does not establish the entire
requirement. Unfulfilled means the required behavior is absent. Live controls
newly added by this audit are **pending new-source CI**, even when their
compilation or grader tests pass. No author's reply alone closes a row.

Paths below are relative to the repository. `relay` means
`crates/agentfw/src/mcp/admission/real_server.rs`; `producer` means
`crates/agentfw/src/mcp/original_create.rs`; `driver` means
`scripts/verify-sou62-real-mcp.py`.

| Source | Required behavior | Implementation | Executable evidence / limit | Status |
| --- | --- | --- | --- | --- |
| Deliver 1 | Separate opt-in pinned ORIGINAL profile; original discovery and schemas | `server_profile/filesystem_create.rs`, installer, `server_profile.rs` | Four profile tests; original manifest equality in installed driver | Confirmed baseline |
| Deliver 1 | Preserve valid original JSON-RPC/tool errors without publishing partial output | Audit found producer converted upstream errors to a generic relay failure; corrected producer returns no verified-output capability for validated error, relay routes original frame through native inspection | `original_errors_never_grant_publication_even_with_partial_stage_artifacts`: JSON-RPC and isError errors, partial output cleanup, false success and hidden error data refusal | Corrected in audit; focused local proof, new-source CI required |
| Deliver 1 | Exact path/content only, <=4096 UTF-8 bytes, no aliases or nested/hidden targets | `filesystem_create::validate_request`, relay input gate | Bounds, Unicode-byte, alias, extra-field unit controls; real refusal cases | Confirmed baseline |
| Deliver 1; ownership | Preserve read-only and Git authority; refuse all other mutators | Profile selection, relay registry validation | `selected_registry_*` authority/schema/family controls; required Git CI | Confirmed baseline |
| Deliver 1 | Record runtime/dependency/schema identities and untrusted provenance | Pinned SOU-62 installation; exact original schema hashes, native registry | Installer/loader controls; install metadata and CI binary/tree identities | Confirmed baseline |
| Deliver 1–2 | All typed resources and exact per-call authority | `CreateSelection` target/byte count/digest; native canonical args and host ID binding; classifier audit | Exact args are bound; original-create still uses `sw-native/1`, not typed `resource_admission` with separately retained resource evidence | Partial task-wide resource-evidence requirement |
| P1 review; Baubek loader comment | Exact native profile/tool/action/registry exception; no relabel workaround | `NativeState::from_bytes` allows only selected `write_file` SideEffecting with exact create registry | `actual_sou83_installer_registry_loads_and_other_mutators_stay_denied`; independent reviewer recheck | Confirmed; closed P1, not changed by audit |
| Same review | Reject action/profile/provenance/schema/egress/resource-policy widening | Native loader and relay `validate_registry` | Full actual Python installer registry plus negative controls in `native.rs` | Confirmed baseline |
| 6289844328; Linear 413083c1 | Preserve main's read-only union; create-only rejects Git peers | Narrow create registry validation | `selected_registry_create_only_does_not_inherit_shared_daemon_peer_authority` | Confirmed baseline |
| Deliver 2 | Missing classifier/unknown semantics/Ask/Deny never publishes | `admit`, scoped classifier composition | Explicit refusal code; native/classifier unit controls; no fallback write | Confirmed fail-closed boundary; not Ask continuation |
| Deliver 2; Baubek; review gate | Single-use Ask continuation bound to session/target/content/epoch | Original-create `admit` returns `classifier_ask` before native call | No original-create approval continuation exists; generic native approval tests are not this path | Unfulfilled full-task requirement; reviewer permits unsupported increment only |
| Deliver 2 | Authenticated native call/result, session epoch and exact host ID/args | Relay `admit`/`inspect`; native session call binding and one-use calls | Existing native replay test; audit adds unused-receipt target/content/host mismatches and terminal spending | Confirmed local native gate; full live new candidate pending |
| Deliver 2,4 | Policy transition cannot publish stale authority | Shared policy boundary held across create; native result policy revalidation | Shared barrier tests exist; no original-create-specific managed epoch transition witness | Partial |
| Deliver 3 | Fresh ORIGINAL server sees only private stage; no retained writable real workspace | `prepare_create_stage`, producer, relay Creating branch | Required actual ORIGINAL ignored test explicitly invoked; installed native create/read/verify | Confirmed baseline |
| Deliver 3 | Read-only runtime/package, no ambient credentials/network | Writable-stage namespace, environment clearing, seccomp | Audit adds active TCP/Unix probes with calibrated receivers and private-stage positive write; runtime/package/outside write refusals | Implementation present; new live proof pending |
| Deliver 3,5 | Reject extra files, wrong bytes, links, special/oversized outputs | Producer `OwnedStage::verify`, nofollow/nonblock regular inode and exact digest checks | Stage unit tests cover extras, mismatch, symlink, size/mode; not exhaustive adversarial upstream transcript injection | Partial full adversarial requirement |
| Deliver 3 | Exact bytes publish atomically without overwrite | Verified output -> existing `PreparedCreate` -> anonymous `stage` -> `linkat` | Original-specific no-clobber test and shared publisher tests; real filesystem snapshots | Confirmed baseline |
| Deliver 3,5 | Existing symlink must not be followed or replaced | Shared publisher nofollow/type checks | Publisher all-leaf-types test; audit adds real installed original target symlink/outside marker control | Confirmed primitive; new integrated proof pending |
| Deliver 3,5 | Root/ancestor substitution and competing creates | Pre-admission `PinnedWorkspace`; shared publisher root check and atomic link | Original root substitution test; shared before/after-stage root and target insertion plus concurrent same-leaf controls | Confirmed primitive; live adversarial original race matrix incomplete |
| Deliver 4; review 6290443329; Linear d503b5d1 | Cancellation during Creating leaves no visible target | Relay cancellation/reclaim; producer only returns verified stage | Real post-Native-Allow Creating cancellation; independent actual filesystem check | Confirmed baseline; retained, not reimplemented |
| Same | Cancel during result inspection and anonymous staging | Relay cancellation/client-EOF/deadline checks and dropped staged capability | Shared publisher drop-stage tests; no deterministic original-create CreateInspected/CreateStaged injection | Partial |
| Deliver 4; review finite gate | Late cancellation/result withholding never claims rollback | Synchronous commit; `committed` error accounting; late cancel is audited | Shared directory-sync-failure test; audit adds late cancel after successful original commit and read verification | Confirmed primitive; new integrated late-cancel proof pending |
| Deliver 4–5; Baubek finite gate | Native daemon loss after Allow prevents publication | Native result gate uncertainty and owned cleanup | Actual Creating daemon stopped, absent target, daemon restart; required baseline CI | Confirmed baseline |
| Deliver 4–5 | Worker/collector/namespace-owner failure at mutation boundaries | SOU-86 owner lease/kill/reap; producer cleanup, no publisher inside producer | Generic/read-only crash tests do not demonstrate every new mutating phase; no complete original worker-crash matrix | Partial; do not infer from daemon loss |
| Deliver 4 | Bounded lifetime, frames, stderr and cleanup; unsupported kernels refuse | 20-second producer exchange, frame cap, bounded stderr, owner/budget cleanup | Producer/control tests; required Linux positive fails rather than skips; local namespace startup actually fails | Confirmed selected limits; no arbitrary-server resource/isolation claim |
| Deliver 5 | Actual unwrapped original calibration before protected create/read/verify | Existing unwrapped original write; audit adds 3 matched UTF-8 create/read samples | Exact original executable/dependency pin; filesystem bytes and client transcript | Baseline original write confirmed; new matched samples pending |
| Review 6290443329 | Host replay must be real spent authority, not overwrite with a new ID | Relay used-ID rejection; native spent-call removal | Existing actual host-ID replay and native byte-identical/tampered result replays; audit extends unused grant mismatch controls | Confirmed baseline and local extension |
| Review finite gate; Deliver 5 | Useful continuation after replay/cancel/failure | Same-session read and restarted-daemon read | Existing real read controls; audit adds new successful create/read after cancellation and after daemon restart | Read confirmed baseline; new write continuation pending |
| Deliver 5 | Independent visible-effects witnesses distinguish committed and refused writes | Driver full workspace snapshots, outside sentinel, private file mode | Four intentional writes expected by new driver; denied/cancelled/outage targets absent; old baseline expected one | Baseline confirmed; changed live scenario pending |
| Deliver 5 | Calibrated egress prevention for create sandbox | Network namespace and writable-stage seccomp branch | Read-only receiver alone is insufficient; new writable-stage active probe requires TCP/Unix receivers remain empty | New proof pending; exhaustive egress injection still partial |
| Deliver 6 | Accurate overhead/failures, no isolation overclaim | Audit adds monotonic matched-payload write-RPC samples, median and ratio | Three warm unwrapped vs three native/fresh-sandbox/durable writes; startup/read excluded; not throughput or model-quality measurement | Measurement instrumentation added; numbers pending |
| Deliver 6; all reviews | Private installation and truthful support docs/PR body | New-only 0700 installer; guide; this audit | Installer unit controls and actual native registry loading; full Ask and unproven fault boundaries explicitly retained | Confirmed installer; docs updated without completion claim |
| CodeQL threads 4315511571/4315957662/4316194545 | No workflow with ambient token permission | Temporary workflows removed from final tree | Four resolved threads include three obsolete workflow findings; current actions CodeQL success | Confirmed resolved by removal |
| Deliver 6; Baubek current-source gate | Required current-source CI, no old green transfer | Existing centrally registered required filesystem job | Baseline run 39447631091: 69 success, 2 expected skips, 1 neutral; filesystem 42/42, combined 15/15 | Confirmed baseline only; new source must pass |
| Last winux125 comment | Separate SOU-103 Windows issue; no blind retry/fix claim | No changes to `profile_lifecycle.rs` | Baseline newer Windows security job 118713737965 succeeds; this does not diagnose old failure | Confirmed scope separation |
| Done; user | No merge/Done/full acceptance without reviewer | Existing PR retained, history preserved | Aggregate CHANGES_REQUESTED; task In Progress; no review request until limits/remaining gates settled | Still a blocker |

## Exact baseline CI independently inspected

GitHub API check-runs for `dcb048b` show 69 successful, two skipped and one
neutral check, none failed/pending. Admission:
[39447620848](https://github.com/SoupTeam/soup-wall/actions/runs/39447620848).
All five CodeQL analyses:
[39447618508](https://github.com/SoupTeam/soup-wall/actions/runs/39447618508).
Full suite:
[39447631091](https://github.com/SoupTeam/soup-wall/actions/runs/39447631091).
Candidate impact identifies `5fd95c0fa8a7b010314ac598063a68e69a27b23c`.

The complete required filesystem job log was fetched through GitHub MCP:
[118713740330](https://github.com/SoupTeam/soup-wall/actions/runs/39447631091/job/118713740330).
Its emitted report confirms clean `dcb048b`, 42 passed, zero failed/skipped;
combined original-server/shared-host controls 15/15 and installed actual-Claude
pilot 12/12, two benign workflows. Artifact 12277413463 exists with declared
digest `37504ebafa933a2b36b4f626773cccecbd7844adeba59e56c6ca26f19a4ce00f`.
MCP retrieved a download reference, but the execution network refused the
artifact download host. The ZIP bytes/digest have **not** been independently
verified in this audit; the fetched job log and actual source were inspected.

## Remaining acceptance decisions

The first audit candidate `d019d3e` failed required filesystem job
[118762618002](https://github.com/SoupTeam/soup-wall/actions/runs/39461705469/job/118762618002):
the new active writable-stage probe timed out. Source inspection found that
the probe waited for the trusted owner's exit before sending its explicit
quiesce/stop handshake. The follow-up fixes that test lifecycle ordering;
it does not increase the timeout, weaken an assertion or retry unchanged
source. This failed result and its artifact 12283287717 remain retained.
The same follow-up preserves valid original upstream errors without giving
them any publication capability. Both changes require new-source CI.

The original task still requires single-use Ask and wider typed-resource,
epoch-transition, worker-crash, stage-boundary and original race qualification.
The reviewer explicitly permits an Ask-unsupported intermediate increment;
that is not agreement to close the entire task. Added kernel/continuation and
latency controls must pass the new candidate's required Linux job. After those
results, winux125/Baubek must decide whether the accurately bounded increment
is acceptable while the remaining SOU-83 requirements stay open. This audit
does not request another review or treat CHANGES_REQUESTED as dismissed.
