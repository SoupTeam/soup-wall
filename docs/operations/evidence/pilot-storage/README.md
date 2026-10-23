# Pilot storage recovery evidence

The [initial native report](native-report-initial.json) contains all 23 required passed cases
from exact clean commit `2e57584c861c0a0ab0c29d2c487598fb4ca0aee8`, tree
`cc1836c254dbf225995954adf8bddb2975f026f1`. The
[native Ubuntu run](https://github.com/SoupTeam/soup-wall/actions/runs/39996830900)
succeeded as a non-root operator. The selected original filesystem/Git servers
and actual Claude Code host used an owned loopback scripted provider.

[Initial verification metadata](verification-initial.json) records the independently checked
archive/report hashes, 81 referenced file hash checks, source identities and
test counts. It also separates WSL unit/helper checks and the native Python
suite's one skipped adjacent cleanup control. The native job's separate cleanup
qualification passed; the 23 storage cases have no skips or missing cases.

The native report retains publication outcomes, calibration, old/new daemon
instances, explicit stale-authority refusal, useful original-server recovery,
zero forbidden FIFO effects, foreign-process/file and workspace snapshots, and
bounded process cleanup. Artifact `12521411043` retains the supporting sanitized
owned logs, wire records, event witnesses and publication traces under the job's
normal seven-day development retention.

Failed attempts are preserved separately:

- [First attempt](first-attempt.json): missing `rustfmt`, before build or host execution.
- [Second attempt](second-attempt.json): required formatting corrections, before build or host execution.

Follow the [operator runbook](../../PILOT_STORAGE_RECOVERY.md) for recovery.
The faults are scoped to disposable owned paths. They do not establish physical
capacity/quota limits, power-loss behavior, WSL full qualification or live-model
effectiveness. Admission and main integration remain reviewer/TL work.

The [independent artifact review](independent-review-initial.json) confirms these
results and records their limits. Detailed file-state maps and the foreign
process identity were originally checked by runner assertions but retained only
as digest/boolean witnesses. A follow-up qualification will retain those safe
owned-state snapshots explicitly, while preserving this initial successful run.
