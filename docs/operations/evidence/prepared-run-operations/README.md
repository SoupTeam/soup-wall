# Prepared-run operations evidence

This directory retains bounded reports from genuine Ubuntu 24.04 runs of the
prepared-run discovery and completed-state archival commands. Each report binds
its tested commit and selected executable hashes. The workflow uses pinned
original Claude/filesystem/Git servers with an owned scripted loopback provider,
ordinary-user disposable state and a private loopback network. No paid provider
or private dataset is used.

The JSON files contain finite outcomes, counts and hashes. Raw process traces,
tokens, prompts/results, runtime directories and private audit archives are
excluded. An archive hash in a report identifies a private test artifact; the
archive itself is never uploaded.

## Qualified source

[Run 40315581525](https://github.com/SoupTeam/soup-wall/actions/runs/40315581525)
passed all 26 native cases on clean source
`2cf3ea9fd2629c83cfbd350342f8627666fd5b19`. The
[bounded report and cleanup result](passed-40315581525.json) retain identical
opening/closing source fingerprints, actual non-root Ubuntu 24.04 kernel
identity, all required case flags, unchanged workspaces/assets and unrelated
process/file survivors. The transient unit was removed with exit code 0.

The Actions artifact is `12646993612`; its ZIP SHA-256 is
`292fba6e52db6f5f98f8ef70c77d30418689b81307d1f7c1a8734eda2bdc83de`.
The downloaded artifact digest, exact Actions head and all required report
fields were independently checked before retaining this result. The same run
passed 24 operations regressions, 12 existing audit checks, nine CI component
checks, Rust formatting and the Rust diagnostic validator test (including seven
rejected snapshot mutations). Existing focused preparation checks also passed.

The native cases include simultaneous authenticated real runs, daemon loss and
fresh-instance observation, useful completed work through both original servers,
retained repeated-stop authority, actual foreign UID state, bounded malformed
and corrupt inputs, real writer-lock refusal, injected `ENOSPC`/`EIO` archive
failures, a syscall-level interrupted deletion and read-only recovery inspection,
three concurrent replacement races, verified archive hashes, exact successful
removal and repeated-apply refusal. The member race observes the delayed staging
syscall while the original source descriptor is open before performing its
replacement. Product deadlines and witness success requirements are preserved.

Subsequent delivery changes retain this evidence and update the CI coverage
guard to recognize the explicit operations dispatch input. The guard continues
to reject unknown conditions and checks that this focused mode cannot replace
ordinary PR lifecycle/audit gates. Executable sources, their operations tests
and the workflows at the qualified revision remain unchanged.

## Retained failures

| Run | Passed native cases | Failure |
| --- | ---: | --- |
| [40307651300](https://github.com/SoupTeam/soup-wall/actions/runs/40307651300) | 5 | Restart/peer observation failed. The next witness completes useful peer work immediately after daemon loss, before preparing another run. Product deadlines and accepted runtime checks are unchanged. |
| [40311250660](https://github.com/SoupTeam/soup-wall/actions/runs/40311250660) | 23 | The member-replacement witness failed its expected-location assertion. Seeing the detached directory did not establish that the member staging syscall had been reached. The next witness waits for that syscall with the selected source descriptor held open. |

The corresponding [first report](failed-40307651300.json) and
[later report](failed-40311250660.json) both retain `native_acceptance: false`.
Their failure labels are assertions from the witness, not proof that a file was
deleted. They cannot establish full qualification. Earlier formatting and
test-fixture preflight failures are also retained in the Actions history; the
fixture was repaired without allowing a group-writable trusted executable.

## Reproduction and limits

Dispatch `.github/workflows/mcp-real-filesystem.yml` at the intended revision
with `prepared_operations_only: true`. The focused lane reuses accepted native
preparation, formatting and Python regressions, the Rust diagnostic projection
test, and the real-host operations witness. It skips unrelated runtime matrices.
The `prepared-run-operations-RUN-ATTEMPT` artifact contains only
`qualification/report.json` and `cleanup.json`.

Successful qualification must bind a clean, identical source before and after,
all 26 required cases, native non-root Ubuntu and private-loopback checks,
unchanged selected assets/workspaces, unrelated survivors, and removed transient
unit state. Check the Actions head revision and artifact SHA-256 independently.
Fixture-only reports from `verify-prepared-run-checkpoint.py` always retain
`native_acceptance: false`; their positive HTTP projection and foreign ownership
controls are explicitly mocked/emulated.

Diagnostic observations retain unknown protection and execution coverage. The
evidence does not establish live-model efficacy. Stop authority remains excluded
from cleanup, and interrupted removal requires read-only inspection and manual
review rather than automatic restoration or purge.
