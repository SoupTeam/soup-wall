# Long-running installed pilot exercise

SOU-127 provides an opt-in Linux x86-64 development exercise of the accepted
original read-only filesystem and Git MCP pilot. It uses the pinned actual
Claude Code host with an owned loopback scripted Messages provider. It measures
host interoperability, useful execution, cancellation, resource retention and
recovery. Live-model effectiveness is **not measured**. No paid provider calls,
personal credentials or private data are needed.

## Repeatable execution

Build and select the exact installed runtime as described in
[installed pilot qualification](INSTALLED_PILOT_QUALIFICATION.md). The same
`sw-installed-pilot-selection/2` sidecar binds the clean source, Agent, Git helper,
original packages, classifiers, explicit accepted pilot policy and test binary.
Do not select another feature branch or a candidate kit.

```sh
python3 -B scripts/qualify-pilot-stability.py
python3 -B scripts/qualify-pilot-stability.py --run --mode smoke \
  --selection /absolute/private/selection.json --strace /usr/bin/strace \
  --expected-commit FULL_REVIEWED_COMMIT --output /absolute/private/new-smoke
python3 -B scripts/qualify-pilot-stability.py --run --mode soak \
  --selection /absolute/private/selection.json --strace /usr/bin/strace \
  --expected-commit FULL_REVIEWED_COMMIT --output /absolute/private/new-hour
```

Without `--run`, the command prints its plan and starts nothing. Smoke executes
the recovery boundaries with a small workload; `smoke-pass` cannot qualify the
hour-long run. Outputs must be new directories outside the checkout. Preserve
failed and aborted directories instead of overwriting them.

The existing [filesystem workflow](../../.github/workflows/mcp-real-filesystem.yml)
has a manual `stability_mode` choice (`off`, `smoke`, `soak`). Default `off`
preserves existing qualification. Selecting smoke/soak runs one disposable Ubuntu
22.04 job and skips the ordinary matrix. The long job is explicitly excluded
from generated PR components and admission. CI admission and integration remain
the team lead's responsibility; this is targeted development evidence.

The workflow pins and builds the same accepted runtimes and uses one owned
systemd service, capped at 2 GiB, 512 tasks, two CPUs and 80 minutes. Its outer
teardown is emergency containment, never successful cleanup evidence. No shared
runner configuration, kernel security setting or unrelated process is changed.
The metadata observer requires passwordless `sudo` in this disposable service:
Linux deliberately prevents an ordinary user from counting FDs of non-dumpable
sandbox owners. The observer reads only numeric metadata of the pinned driver
and its independently discovered descendants; it reads no environment, FD
contents or credentials. Missing privilege or observations fails the run.

## Frozen workload and measurements

`frozen-plan.json` records the complete workload and resource/recovery ceilings
before execution. Qualification requires a full 3,600 seconds and twelve rounds
at five-minute intervals. Each round runs two actual host conversations; each
conversation completes ten mixed filesystem/Git workflows. Every workflow
observes both original tool results with exact expected bytes. The denominator
is **240 completed workflows / 480 useful original calls**, with zero benign
interruptions. A final useful two-server workflow checks the end of the hour.
Each host result is checked against discovery-calibrated collector write syscalls
for the exact tool and arguments. The trace also observes network syscalls;
non-loopback destinations fail the run. The loopback receiver is positively
calibrated and must receive no forbidden delivery.
Before and after the hour, actual-host derived-read Ask and unsupported Git reset
must have zero original-server dispatch, while useful follow-ups and the same
read in an independent conversation must still work.

The shipped scheduler, authority TTLs, liveness leases, policy and provenance
limits are unchanged. Fresh short-lived conversations replace collectors; the
exercise does not grant hour-long authority. The original pilot retains its
shipped 8 MiB per-context / 64 MiB total provenance defaults. Authenticated
capacity snapshots record actual usage and active collectors every five seconds.
Independent procfs samples record owned process identities, FDs, threads and RSS
every second. A controlled child with 32 extra FDs and four extra threads
calibrates the observer before qualification. Empty, stale, inaccessible and
unsupported observations cannot become safe measurements.

Frozen sampled ceilings are 96 processes, 2,048 FDs, 256 threads and 1.5 GiB
aggregate RSS. Quiet checkpoints before the declared daemon replacement must
retain the same process count; FD range is at most 32, thread range 16 and RSS
range 128 MiB. These are experiment acceptance ceilings, **not a claim of kernel
enforcement by the unbudgeted default pilot**. The outer service supplies separate
emergency containment. RSS and charged provenance bytes measure different things.
Finite sampling does not prove the absence of shorter peaks.

Declared fault rounds are:

| Round | Exercise | Required recovery |
| --- | --- | --- |
| 2 (10 minutes) | Eight actual blocked filesystem reads, queued and active cancellation | Queued call never executes; useful sibling and same-session follow-up |
| 4 (20 minutes) | Kill one owned useful collector after reading an untrusted path | Production cleanup, lease reclamation within 15 seconds, useful sibling, fresh epoch, sticky derived-read Ask and useful follow-up |
| 6 (30 minutes) | Kill the exact owned original filesystem server through a pidfd | Bounded descendant cleanup, useful Git sibling and fresh-authority read |
| 8 (40 minutes) | Daemon outage before a forbidden FIFO proposal | No FIFO execution, explicit old-grant instance mismatch and useful fresh conversation |
| 10 (50 minutes) | Accepted SOU-72 provenance-pressure control on the same binary | Saturation/eviction, sticky Ask after reclamation, hard Deny, independent publication and capacity recovery |

The provenance-pressure control is the accepted **owned generic MCP** exercise,
with deliberately small explicit limits; it is recorded separately from the
default-limit original filesystem/Git workload. Its thirteen independently
graded checks cover early-reference eviction, unrecordable-result withholding,
single-use approval without clearing incomplete history, shared history after
child exit/reconnect and hard Deny. It does not substitute generic servers for
the sustained original-server workload. Actual server results and benign
expectations are never relaxed to pass a gate.

## Evidence and operator recovery

Each iteration is written immediately, including an incomplete/failed state.
The final report records the frozen-plan digest, exact source and selected asset
hashes, completed/failed workflow denominator, interruptions, resource peaks,
native samples, fault witnesses and cleanup. `process-samples.ndjson` retains
numeric process metadata. Original synthetic host/provider results and redacted
collector/audit logs support review. Raw syscall traces and capabilities stay
private; no host configuration or inherited credentials are published. The
workflow retains failed attempts as well as successful ones for seven days.

On a failure, retain the output directory and inspect `failure.txt`, the failed
iteration and its owned logs. Do not increase limits or timeouts to conceal
growth. Reproduce and fix the owning lifecycle module, then repeat only evidence
affected by the source change. A shorter smoke or an old commit's hour cannot
qualify a changed runtime.

After collector/server death, wait for owned cleanup and lease reclamation, then
start a new collector with fresh authority. A surviving sibling must remain
useful. After daemon loss, start the daemon and a **new conversation** with fresh
instance-bound authority. Old grants and the old context are not resumed. An
in-flight cancelled read may already have executed; cancellation is not rollback.
Never kill a process using only a remembered PID or clean another operator's
session. Failed cleanup remains failed even if outer service teardown removes it.
