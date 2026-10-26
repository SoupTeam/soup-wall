# SOU-142 owner-self-loss handoff evidence

Native diagnostic status: **pending**. No new native fault result, production
cleanup success, full SOU-142 acceptance or shared admission is claimed.

The [control and boundary](../../PREPARED_BUDGET_OWNER_SELF_LOSS.md) describe the
actual-owner SIGKILL before SCM_RIGHTS handback, distinct from the accepted four
collector-parent-loss cases. The manual `owner-loss` phase retains a blocked or
incomplete outcome; observer fixture cleanup never becomes production recovery.

The [local ledger](local-attempts.json) records source/log digests and every
attempt. Local macOS results qualify observer parsing, finite projection and
cross-platform compilation, not the Linux process/cgroup boundary. Full Rust
workspace passed 1810 tests with 13 existing ignores; strict workspace/all-target
Clippy and fmt/docs/generated workflows passed. The supported local Python run
ran 1562 tests: 96 explicit unavailable-platform skips and all remaining tests passed. Ten of those skips
are Linux `/proc` lifecycle/status methods in the external local harness only;
the repository tests and mandatory Linux CI remain unchanged.

Two failed local Python attempts remain failed: initial CLI lookup was not linked
to the scratch target, then four newly accepted Linux `/proc` status controls
were unavailable on macOS. The CLI lookup and external platform accounting were
corrected; no production code, expected status, deadline or limit was weakened.
The first native attempt, run `40282553955` on `2d6dad6`, passed the Linux
build/unit/strict-Clippy/adoption slice, but failed before the fault observation:
an enclosing attempt filename was shadowed by a per-case destination. A second
collision between runner and collector private log names was found during review.
The case loop is now isolated from the attempt serializer and collector logs have
their own names. Regressions exercise the actual case runner/checkpoint flow and
actual observer setup through exclusive log creation, stopping before any fork.
The failed run remains in [the native attempt ledger](native-attempts.json), with
independently verified ZIP SHA-256 and CRC. It is not an owner-loss result.
