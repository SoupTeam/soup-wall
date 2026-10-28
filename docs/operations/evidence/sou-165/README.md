# SOU-165 result admission measurements

Accepted independent source: `f4937110b58305645b7302acae99325d13354916`.
The original failed attempt and unchanged successful repeat are both retained
in `historical-observations.json`; passing a retry is not a causal correction.
The native workload and finite denominator are frozen in `trial-plan.json`.

The instrumentation-only baseline changes no detectors, policy, grants, scan
budgets, result bytes, state ordering or deadlines. Native timing rows use
monotonic microseconds and fixed fields/digests only. `release_decision` is a
server decision, **not** proof of delivery. Collector transport and actual
stdio delivery have separate observations. Service `state_and_decode_us`
includes decoding, validation, state manipulation and small unclassified
bookkeeping; it does not pretend to be a detector measurement. Enqueue age is
observed at the existing collector stages; queued time remains inside the
unchanged call lifetime. No new queue, cache, concurrency or authority exists.

Local in-process stage profiles identify a provenance-work bottleneck but are
not native Linux acceptance. The opt-in `manual-native-result-profile` job
builds both immutable sources with Rust 1.94.1, dev and release, then runs
private-loopback-only native trials with read-only source and owned writable
scratch. Neither the ordinary required matrix nor runner host protections are
changed. The source, compiler, binary hashes, CPU affinity, load, all failures,
refusals and unattempted denominator are retained. No universal latency claim
or attribution of the historical failure to a source regression is justified.

The first candidate replaces full-width remainder in the rolling provenance hash
with mathematically equivalent Mersenne folds and avoids repeating identical
adjacent set insertions. It still computes every rolling window and retains
exactly the same sorted fingerprint set. An independent legacy implementation
checks full-width arithmetic, Unicode and complete inputs through 1 MiB.
Provenance recording, limits, lifetimes, locks and verdict rules are unchanged.
Local stage observations (including incidental test executions) are retained
in `local-stage-observations.json`; the completed native comparison is recorded below.

The original enclosing `bwrap --proc` masked procfs submounts and prevented the
unchanged nested product sandbox from mounting its own procfs. All 18 startup
refusals remain in the development history. `enclosure-probe.json` establishes
the cause with a separate bounded `/bin/true` probe, not a latency claim.
The trusted enclosing setup now mounts a fresh `nosuid,nodev,noexec` procfs in
its private PID/mount namespace, then drops to UID 1001, all capabilities zero
(including bounds), and NoNewPrivs=1. Source/filesystem writes remain refused;
only owned scratch is writable. Kernel-virtual procfs operations needed to
construct child namespaces do not modify host configuration. No host sysctl,
AppArmor profile or product sandbox guard changes. An actual original-MCP
startup/read/cleanup smoke now precedes the remaining expensive paired builds.

The first actual paired comparison reproduced the debug timeout: both baseline
and arithmetic-only candidate passed 3/6 dev bursts and 3/3 distribution bursts.
The complete candidate inventory passed; the baseline closed after 19 cases.
The complete finite denominator and every trial's stage observations are retained
in `first-candidate-measurements.json`. That candidate was not stable enough.

Complete evidence and detector scans dominated the remaining dev work. The
measured correction therefore also compiles the same pure `soup-wall-core` and
`soup-wall-agent` crates at opt-level 3 in the dev profile, like the existing
same-FD SHA-256 dev optimization. Debug assertions and overflow checks remain
explicitly enabled. The daemon/transport profile, exact original-byte scanners,
policy/thresholds, lock ordering, provenance retention and every lifetime remain
unchanged. This corrected source was qualified by a fresh full paired comparison;
the earlier successful inventory is not substituted for it.

Final targeted run `40574476228` at clean source
`929b863abbade7e7dd9c035a7e387d39fde59283` is independently verified.
The corrected candidate passed all 9/9 trials and the unchanged full 21-case
inventory, including the genuine Claude scripted-provider sequence. The baseline
passed 8/9 trials, with its remaining contended-debug timeout retained, and its
full inventory passed. Total denominator is 18 attempted, 17 passed, 1 failed,
0 incomplete; this is not represented as an 18/18 success. The candidate's 81
result HTTP observations were at most 3.126115 seconds under the unchanged
5-second request deadline. Build time is reported separately. No universal
latency claim follows from this finite run.

`native-summary.json` contains environment, source/binary identities, complete
denominators, per-stage medians, independent checks and support limits.
`native-trials.json` retains every response digest and native/transport/delivery
observation, including the baseline failure and verified process cleanup.
`native-inventories.json` retains both complete existing original inventories.
The full raw reports/logs remain correlated to artifact `12767717781`, archive
SHA-256 `4b289bdfa00fd97137dac20fcde620a1ea43fdda550bf596df2d2d52242361ae`.

Native Rust checks: 525 passed, 0 failed, 0 ignored; strict Clippy and fmt passed.
Local workspace: 1907 passed, 13 existing ignored; strict Clippy and fmt passed.
The earlier local socket calibration failure remains in the development history.
Final shared Ready qualification, admission and merge remain TL-owned.
