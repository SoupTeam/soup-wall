# Linux budget process-lifetime observations (SOU-136)

This correction concerns the shared Linux budget observer only. Memory, PID,
CPU and wall controls, 25 ms polling, 3 s cgroup cleanup, independent namespace
owners and exact native authority remain unchanged. Development stays Draft;
final admission and merge belong to the team lead.

## Retained failure and deterministic reproduction

Run 40070626603, job 120803093822, artifact 12551851795 failed on original Git
client `churn-git-53` before initialization completed. Six initial checks and
123 completed churn clients preceded the failure. The budget recorded
`member_open` / `ESRCH`, while cleanup was confirmed and OOM/PID-limit counters
were zero. Its budget module blob is identical to accepted main `8485a51`;
this work does not depend on the corpus or Ask feature branches.

The retained regression patch adds an opener seam to that accepted member-open
decision without changing its errno handling. A real child is pinned through its
proc directory, killed and reaped before a relative `cgroup` open; Linux returns
`ESRCH`. Injecting that actual error at the accepted open decision must fail the
regression. This is a deterministic real-kernel boundary injection, **not** an
unmodified end-to-end reproduction of the historical scheduling. Compilation
failure, timeout or a different errno cannot satisfy the before-fix control.
The candidate exercises the same departed-directory boundary plus fresh
membership and liveness observations.

## Kernel-lifetime argument

The kernel's [`cgroup.procs` contract](https://docs.kernel.org/admin-guide/cgroup-v2.html#organizing-processes-and-threads)
permits unstable order and duplicate numeric PIDs during migration or reuse.
Enumeration is therefore an observation, not a process-lifetime handle.
The [procfs contract](https://docs.kernel.org/filesystems/proc.html#process-specific-subdirectories)
states that an open PID-directory/file descriptor does not retarget a replacement
process. It also does not prevent numeric PID reuse. These are different claims.

Before creating a budget leaf, the collector pins genuine procfs and checks its
filesystem, device, types and PID-namespace relationship (`self` and a single
matching `NSpid`). PID directories and records are opened relative to that root
without following ordinary symlinks. Every sampled member supplies readable,
well-formed identity through the same directory as its cgroup record. The
attachment-time leader directory remains pinned; inode identity and start ticks
are both checked instead of adopting a numeric replacement.

A lookup `ENOENT`/`ESRCH`, or the reviewed pinned-record read `ESRCH`, is only a
departure candidate. Acceptance requires a fresh bounded enumeration from the
same owned leaf excluding that PID, followed by current proc/pidfd observations:
no addressable process, or the same pinned terminal task with an exited pidfd.
A closing lookup cannot adopt a different PID-directory inode, even when start
ticks match. [`pidfd_open` and polling](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
provide the independent current-lifetime check; without `PIDFD_THREAD`, readiness
requires the whole thread group to exit.

Observed live or replaced tasks, a still-listed PID, permissions failures,
malformed/oversized data, unexpected proc device/type, unreviewed read errors and
unexpected poll events refuse. There is no whole-call retry, sleep, broader
budget or authority fallback. A mismatching cgroup with a still-nonterminal stat
also refuses, even if the task subsequently exits.

If exit precedes acquisition of any lifetime handle, numeric enumeration cannot
recover the original historical start identity or exclude an entirely unobserved
reuse. The claim is bounded **current absence plus leaf absence**, not historical
attestation. Changes after the final observation remain the documented sampling
and trusted-host-manager boundary. Kernel aggregate enforcement and owner cleanup
remain active independently of these diagnostic observations.

## Qualification and evidence boundaries

Focused Ubuntu qualification requires 70 distinct original filesystem and 70
original Git crash/reconnect cycles, correlated useful work after restored
capacity, surviving useful siblings, and independently observed cleanup. Separate
owned fixtures calibrate real memory/PID-limit refusals. A separate native Rust
control moves its own unreaped child between owned cgroups and verifies the
production budget observer refuses the violation. The parent retains sole reaping
ownership during migration, so a reused numeric PID cannot redirect its write.
That control establishes the budget predicate and cleanup, not an MCP transport
result. These calibrations never stand in for an original server. Every attempt is checkpointed before
construction. Failed and unattempted work stays failed/incomplete; passing retries
cannot replace it.

The manual `budget_membership_only` workflow input selects this focused lane.
Ordinary workflow defaults retain their full existing checks. It does not run a
broad qualification matrix or perform final admission. Until its native reports
are available, local parser/grader checks are development evidence only.

Evidence is retained under [sou-136](evidence/sou-136/README.md). Diagnostics carry
only fixed phase/error codes and bounded numeric observations; no raw proc status,
private payload, authority token or process-metadata dump is exported.
