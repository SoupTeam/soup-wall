# Pilot storage recovery evidence

The [final native report](native-report.json) contains all 23 required passed cases
from exact clean commit `7008678508c180f25fdffb97bc900b1d8a70ef39`, tree
`cf18b6813fc31bdef2fefce2bd6d1dd6af51ecab`. The
[native Ubuntu run](https://github.com/SoupTeam/soup-wall/actions/runs/39999978938)
succeeded as a non-root operator. The selected original filesystem/Git servers
and actual Claude Code host used an owned loopback scripted provider.

[Verification metadata](verification.json) records the independently checked
archive/report hashes, 106 file reference checks covering 94 unique files,
nine publication traces, source identities and test counts. It separates the native Python
suite's one skipped adjacent cleanup control. The native job's separate cleanup
qualification passed; the 23 storage cases have no skips or missing cases.
The [final independent review](independent-review-final.json) rechecks the
contracts and all 13 raw state snapshots from the downloaded archive.

The native report retains publication outcomes, calibration, old/new daemon
instances, explicit stale-authority refusal, useful original-server recovery,
zero forbidden FIFO effects, foreign-process/file and workspace snapshots, and
bounded process cleanup. All 13 detailed owned-state snapshots were independently
compared: filesystem/Git maps, foreign file and process identity stayed equal,
and receiver journals were empty. The [baseline and final state maps](state-snapshots.json)
remain in this PR along with all 13 original snapshot references. They contain
metadata and content hashes of synthetic owned workspaces, not daemon home,
configuration, tokens or authority. Artifact `12522700825` retains the supporting sanitized
owned logs, wire records, event witnesses and publication traces under the job's
normal seven-day development retention.

Failed attempts are preserved separately:

- [First attempt](first-attempt.json): missing `rustfmt`, before build or host execution.
- [Second attempt](second-attempt.json): required formatting corrections, before build or host execution.

Follow the [operator runbook](../../PILOT_STORAGE_RECOVERY.md) for recovery.
The faults are scoped to disposable owned paths. They do not establish physical
capacity/quota limits, power-loss behavior, WSL full qualification or live-model
effectiveness. Admission and main integration remain reviewer/TL work.

The [initial report](native-report-initial.json),
[initial verification](verification-initial.json) and
[initial independent review](independent-review-initial.json) preserve the earlier
successful run on `2e57584c`, before detailed snapshot retention was added. WSL
unit/helper evidence is recorded separately there and is not native acceptance.

This evidence is added after the final qualified commit. Only evidence
documentation changes follow that commit; no runtime or qualification source
changed after the final native run.
