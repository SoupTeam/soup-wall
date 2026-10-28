# Concurrent native original-result admission

SOU-165 preserves the existing supported result envelope (1,048,576 wire bytes)
and decoded per-result text limit (262,144 bytes), eight active original calls,
eight queued calls, the native HTTP deadline of five seconds, and all existing
call, parent, session and human approval lifetimes. Original bytes and both
original filesystem result channels undergo the unchanged complete inspection.
Oversized results produce a correlated refusal; a fresh useful call can follow.

The correction preserves the computation's result while reducing its cost.
Debug builds compile the same pure detection and provenance crates with
opt-level 3; debug assertions and overflow checks remain explicitly enabled.
Native profiling reproduced dev timeouts in both the old and arithmetic-only
candidate while distribution builds completed all declared bursts. Pure scanner
and evidence work dominated after the first arithmetic reduction. This build
profile correction does not change the daemon's timers, transport, scanner
rules, labels, thresholds, authority or memory budgets.

The arithmetic correction preserves the Rabin–Karp
modulus, canonicalization, window, selected fingerprints, literal tracking,
sequence order, policy evaluation, evidence budgets, sticky history floors and
retention accounting are unchanged. Replacing full-width remainder with exact
Mersenne folds reduces arithmetic work. Avoiding consecutive duplicate set
insertions reduces redundant tree operations. There is no cross-request cache,
parallel state commit or reusable inspection authority.

Timing diagnostics are fixed-size JSON lines with monotonic durations, static
stage/outcome codes and digests. Session/call identity, content hash, enqueue age,
mutex waits, evidence scan, detectors, provenance tracking, audit and transport /
stdio delivery observations can be correlated without printing raw contents,
private paths, credentials or authority tokens. A daemon release decision does
not prove that the collector received a response; received receipts and written
host bytes have separate observations. Logs remain subject to the enclosing
service's retention and operational controls.

The executable benchmark declares and retains a finite old/candidate comparison
on synthetic public data through the pinned original Linux filesystem server.
Debug and distribution profiles are reported separately. Build time is excluded
from runtime latency and retained separately. Owned CPU contention is explicit;
shared-runner load is observed, not asserted to be perfectly reproducible.
Successful-run medians exclude failures only in the named metric; the same row
always includes the attempted / failed / incomplete denominator. An unchanged
historical repeat passing is not evidence that it fixed the earlier timeout.

This is not a guarantee of sub-five-second latency under arbitrary host load.
Timeout, cancellation, refusal, expiry, policy change, lost authority and restart
remain fail-closed. No paid inference, private dataset, classifier threshold,
new platform, host privilege relaxation or runner ruleset change is required.
The enclosing lab uses a fresh procfs in a private PID/mount namespace because
masked enclosing procfs submounts prevented the unchanged nested product
sandbox from mounting its own procfs. A short classified probe retained both
failures and the successful namespace-local correction. Trusted setup performs
that mount before dropping to non-root, zero capabilities (including bounds),
and NoNewPrivs=1. Ordinary filesystem writes outside owned scratch remain
refused; required kernel-virtual procfs operations remain namespace-scoped.
No host sysctl, AppArmor profile, runner or product guard is modified.

The final targeted native run passed the candidate's 9/9 declared trials and
both complete 21-case inventories. The original baseline still failed 1/9
trials. All 18 attempts remain visible: 17 passed, 1 failed, 0 incomplete.
Across 81 candidate result requests the maximum observed transport duration was
3.126115 seconds, below the unchanged 5-second native HTTP deadline. The timer
applies to each native HTTP request; total burst time also includes classification,
server reads, existing queue stages and host delivery.

The three-repetition medians below include successful bursts only, with failure
counts shown alongside. They are observations on the recorded runner, not a
population latency estimate or evidence that arbitrary CPU load is supported.

| Condition | Baseline pass/fail | Candidate pass/fail | Baseline median burst | Candidate median burst |
|---|---:|---:|---:|---:|
| dev, idle | 3/0 | 3/0 | 5468.5 ms | 3316.7 ms |
| dev, two owned CPU workers | 2/1 | 3/0 | 5667.4 ms | 3613.7 ms |
| distribution, idle | 3/0 | 3/0 | 755.4 ms | 731.9 ms |

In idle dev observations the median detector phase decreased from 253896 to
113607 microseconds, and provenance tracking from 174761 to 21201 microseconds.
Complete evidence scanning remained approximately unchanged (162781 versus
162848 microseconds); it was not skipped or relabelled. Session/firewall waits
were negligible in these service rows. Together with the longer collector
transport/queue age, this is consistent with backlog before the synchronous
inspection is polled; a mutex-wait counter alone does not measure that backlog. Neither queue
time nor body work is moved outside any existing deadline by this correction.

Use the opt-in manual profiler while Draft; it is outside the required ordinary
component matrix. Locked runtime assets are prefetched without package lifecycle
scripts. The job enforces read-only source, owned writable scratch and private
loopback networking, builds each source/profile into a distinct output root,
checks the actual original MCP startup before remaining builds, and runs the
unchanged bounded plan. No inference provider is contacted.

```sh
gh workflow run mcp-real-filesystem.yml --repo SoupTeam/soup-wall \
  --ref codex/sou-165-concurrent-result-admission \
  -f native_result_profile_only=true \
  -f native_result_baseline_sha=68d5ea479256e91e3c4890982fd26b407b3cdf73
```

The executable `scripts/benchmark-native-results.py` accepts an exact four-build
manifest plus pinned Node/npm/bubblewrap/strace/Claude paths, offline npm cache
and a new output directory outside the checkout. It retains every attempted row
before starting work. Its 90-second outer trial stop is diagnostic cleanup only;
the product's five-second transport and other existing lifetimes are unchanged.
The per-variant full inventory runs once after the paired bursts. Failures are
retained, never retried into the same measurement row.

Qualified source: `929b863abbade7e7dd9c035a7e387d39fde59283`, run `40574476228`,
artifact `12767717781`, archive SHA-256
`4b289bdfa00fd97137dac20fcde620a1ea43fdda550bf596df2d2d52242361ae`.
English evidence and all development outcomes are under
`docs/operations/evidence/sou-165/`. Final shared Ready qualification, current
source admission and actual main merge remain the team lead's responsibility.
