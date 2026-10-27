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

The candidate replaces full-width remainder in the rolling provenance hash
with mathematically equivalent Mersenne folds and avoids repeating identical
adjacent set insertions. It still computes every rolling window and retains
exactly the same sorted fingerprint set. An independent legacy implementation
checks full-width arithmetic, Unicode and complete inputs through 1 MiB.
Provenance recording, limits, lifetimes, locks and verdict rules are unchanged.
Local stage observations (including incidental test executions) are retained
in `local-stage-observations.json`; native paired measurements are pending.

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
