# SOU-17 CI lifecycle follow-up — 2026-10-14

Owner: konung3. Review coordinator: Nari_Ab.
PR: [#113](https://github.com/SoupTeam/soup-wall/pull/113).
Roadmap: R06, bounded P01–P02. Internal verification, not a release.

Hosted CI rejected PR head `4911e989cc74cbac2a7cc3f46324d899b67733e0` after the
earlier [bb64321 local verification](sou17_candidate_bb64321_2026-10-14.md).
The old report and its raw local successes remain unchanged. Those successes
did not establish hosted-platform acceptance and do not override the retained
CI failures below. SOU-17 remains open.

The correction candidate is **`6a57befbdabdbf5a0571594a0eca4072a4a13126`**, following
merge `853bcaf99d708346ed00dca800c26f1e750ad7d8` of newer main
`6ee33d3ed3a9f73c9fcbf188108b9bdf850f7940`. The merge retained the strict resource
grader and its pre-reservation unsupported-executor expectations. Final exact-source
runtime checks pass locally on that clean source. Required new-head hosted CI, review, scan disposition and affected-main acceptance remain pending.
A later code change requires its own affected rerun.

## Retained original CI failures

| Platform/job | Observed failure |
| --- | --- |
| [Native macOS](https://github.com/SoupTeam/soup-wall/actions/runs/38611256227/job/116015254525) | `sequential_resource_failures_keep_useful_same_session_continuation` failed its final grader: collector did not close cleanly; one test failed after 40.30 seconds |
| [Linux ARM64](https://github.com/SoupTeam/soup-wall/actions/runs/38611256047/job/116014904395) | `sou15_generic_resource_executor_refuses_both_destinations` received no reply and unwrapped `None`; one test failed after 0.08 seconds |
| Same ARM64 job | `sou15_post_admission_read_failure_capacity_leak_prevented_and_continuation_succeeds` received no reply and unwrapped `None`; one test failed after 0.31 seconds |

These are distinct retained outcomes. The macOS failure is a shutdown/complete-
evidence failure, not proof of forbidden execution. A missing response alone is
not proof that nothing ran; reconcile native gates, side-effect witnesses and
released bytes separately. The rejected head had 27 successful checks and two
failed jobs. No infrastructure skip or same-head rerun has been substituted for
these failures.

Ten corrected local repeat runs against the original implementation passed all
nine existing `sou15_*` tests per run. Three new rapid sequential modes also
passed when run against original `bb64321`. These local observations **did not
reproduce the hosted failure** and are not presented as red/green evidence for
its exact cause. The first local attempt used the wrong package/test target and
failed before running any test; that invocation error is retained separately.

## Transport finding and repair rationale

The earlier resource writer waited on Tokio's blocking stdout worker. A client
can physically receive the first response's LF and immediately send its next
legitimate sequential request before that worker publishes completion to its
async future. The old overlap guard could therefore see new input while its
writer still appeared pending. Completion of a blocking-worker handle is not
the same event as physical visibility of the completed protocol frame.

The pinned Tokio 1.53.2 source also documents that its standard-input adapter
uses a blocking thread whose read cannot be cancelled and can delay runtime
shutdown. This is a reviewed transport/lifecycle risk. **Neither that documented
risk nor the stdout timing analysis proves the exact cause of the original
40.30-second hosted shutdown failure.** Preserve that uncertainty and the
original hosted evidence.

Unix native admission now uses owned, close-on-exec descriptor duplicates with
direct nonblocking read/write syscalls registered through `AsyncFd`. Dropping a
pending read leaves no blocking stdin worker holding shutdown open. A successful
write reports bytes actually accepted by the OS; there is no deferred worker
buffer publishing LF before its completion acknowledgement. The resource writer
retains one in-progress operation across EOF and prioritizes completed physical
frame delivery over a simultaneous next sequential input. Descriptor status flags
are restored on drop and failed registration. Windows retains its legacy transport;
this correction does not establish Windows parity or expand the bounded resource
executor to that platform.

The new rapid LF controls submit each next request immediately after receiving the
complete previous frame, with no artificial worker-completion delay: 32 successful
reads; 72 total calls in the error mode (two useful reads and 70 read errors); and
33 total calls in the refusal mode (16 refusals and 17 useful reads). Each mode
retains EOF/cleanup witnesses. Existing overlapping complete/partial frames, cancellation,
large replies and EOF controls remain required. During unsupported overlap, an
already-permitted first read and any already-written pipe bytes remain honest
effects; a later refusal cannot retract them. Do not reuse the old transport's
fully drained first-response observation as a guarantee for the new transport:
the new adapter may abort a partially emitted authorized first response while
preventing the second execution.

An early native macOS descriptor test expected a complete status-word equality
after a real write. [Apple's kernel flag definition](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/fcntl.h)
includes the read-only `FWASWRITTEN` status bit,
so that expectation conflated kernel-maintained history with restorable descriptor
flags. The retained diagnosis distinguishes those values. Final controls retain
full no-I/O status restoration, a complete after-I/O status-word comparison that
restores only the introduced `O_NONBLOCK` bit while preserving kernel-maintained
bits, and close-on-exec ownership checks; existing enforcement assertions are not
weakened. This test expectation correction is separate from the hosted MCP failures.

## Unix stdio requirement

Unix `--native-admission` requires stdin/stdout pipe or socket descriptors that
can be registered for readiness. Ordinary MCP hosts and subprocess clients should
launch it with OS pipes, as the repository fixtures do. A terminal or regular-file
stdin/stdout redirection is explicitly refused; there is no fallback to the
legacy relay. Store results by draining the host's stdout pipe into a file in
the client, and keep diagnostics on stderr. Original MCP IDs, argument bytes,
classification/policy authority and supported external frame shapes are unchanged.

## Exact clean-source results

Tree: `742501cd455805a000b95c94268dcec6a0d73a15`. Frozen `agentfw` SHA-256:
`a10e4639854b33a5f2d725e4551a8c0fc6406ec446ed7af8795b3e7e27191eb0`.
Input digest: `a20c04bf5722014423d3d4245862e1a495847a2f0ebe31bf21b544407938a424`.
Source/binary identities match before and after every final profile; the candidate
remained clean until this documentation update. Runtime ledgers, original IDs/bytes,
independent effects and cleanup are retained in the raw outcomes.

| Check | Raw outcome |
| --- | --- |
| Exact production boundary launcher | 126/126: 19 adapter, 59 MCP admission, 37 native, 11 concurrency; zero failures, timeouts or skips |
| Constrained resource profile | 10/10, including 70 admitted read errors followed by useful continuation |
| Generic classifier/profile | 15/15; four executions and 505 original result bytes |
| Pending admission/overlap | 11/11 |
| Refusal capacity | 64 Ask calls never execute; subsequent useful call executes once |
| Unix stdio unit controls | 3/3 |
| Full workspace, default features | 1,030 passed, zero failed, eight ignored; 52 target results |
| Formatting / workspace all-target Clippy | Passed |
| Python scripts | 476 run: 451 passed, 25 skipped (15 selected Linux TLS runtime, five optional Playwright, five native Windows) |
| Python benchmarks | 44 run: 28 passed, 16 individual skips plus two additional class-level skip records |

Ignored checks and unavailable environments are not passing acceptance evidence.
The earlier report's description of ten Python skips as all native Windows was
inaccurate: its original logs record five optional Playwright and five native
Windows skips. The 15 additional Linux TLS skips come from newer main.
The benchmark summary's 18 skips includes the two class-level records outside the
44 test methods; subtracting 18 from 44 would miscount passed tests.

Thirty serial pairs compare a direct local child-backed read fixture with its
protected production path. No other runtime probe or build ran during this sample.
All 60 rows reconcile final execution/result witnesses: zero false interruptions,
failed, incomplete, unknown or anomalous rows. Startup/warmup are excluded;
per-call Python classifier startup is included.

| Milliseconds | Direct | Protected | Paired overhead |
| --- | --- | --- | --- |
| p50 | 0.217416 | 39.683041 | 39.493000 |
| p95 | 0.297791 | 51.645250 | 51.366416 |
| p99, nearest rank | 0.312291 | 57.490292 | 57.346126 |
| Mean overhead | — | — | 40.625382 |

This sample is not population false-block rate, classifier accuracy or the inline
resource executor's performance. No numeric latency gate was agreed. The
[structured report](sou17_ci_lifecycle_2026-10-14.json) and
[raw archive](sou17_ci_lifecycle_2026-10-14_raw.tar.gz) include original hosted
failures, local repetitions, complete new profile rows and test/build logs.
Archive entries have SHA-256 hashes in `MANIFEST.json`; every entry was verified
and selected logs matched zero credential patterns before publication.

## Acceptance still required

New hosted CI and required review must pass on the reviewed revision, then identify
actual merged main and rerun affected checks. The earlier CodeQL triage is not
refreshed or broadened by this lifecycle supplement and is not a clean scan of this
new source. SOU-17 remains open while accepted limits, scan disposition, review or
required platform checks remain unmet. Later CI/review updates belong in the linked
PR/task so a documentation-only status edit does not repeatedly restart CI.

## Reproduce

Use a clean exact checkout and prerequisites from [DEVELOPMENT](../../DEVELOPMENT.md).
Fresh output, canonical macOS `TMPDIR`, locked dependency cache and owned loopback
listeners are required. The previous report's
[full reproduction procedure](sou17_candidate_bb64321_2026-10-14.md#reproduce-the-repaired-candidate)
applies with `SOU17_COMMIT=6a57befbdabdbf5a0571594a0eca4072a4a13126` and fresh
build/output directories. In the clean checkout run:

```sh
python3 scripts/verify-sou17.py --expected-commit 6a57befbdabdbf5a0571594a0eca4072a4a13126 --offline --out "$SOU17_OUT/exact"
cargo test --locked --workspace --offline
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 -m unittest discover -s scripts/benchmarks -p 'test_*.py'
```

Run the resource, generic, pending, capacity and serial latency commands in the
linked full procedure against that same frozen binary. The launcher includes rapid
LF success/error/refusal, EOF, FIFO and resource backpressure controls. Preserve
failed attempts before reruns and verify raw archive hashes in a fresh extraction.
