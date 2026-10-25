# SOU-142 verification ledger

Task-specific native controls **passed** on source
`77044075f3ae0af2cbe1ef0f5696710e7ad585ee`, based on reviewed main
`04efdf1d959599238a0a9a3eb42cbe26b3531b74`.

`qualification.json` joins two independent public projections on the same source
and identical selected binary hashes. Workflow 40173141964 passed 11 main cases,
four collector-parent-loss controls and four emergency-stop cases. Workflow
40173144358 passed all six original filesystem/Git memory, PID and wall controls.
Each pressure case requires independent original-runtime kernel observations,
the bound closed refusal, surviving useful peer, fresh prepared recovery and
empty owned roots. No observer performed cgroup cleanup.

| Original server | Memory: kernel OOM kills / peak | PID: max events / task peak | Wall refusal |
| --- | --- | --- | --- |
| filesystem | 3 / 64 MiB | 1 / 16 | confirmed |
| Git | 4 / 64 MiB | 2 / 16 | confirmed |

The limits, eight MCP proposals, policy floors and timeouts were not relaxed.
Both phases keep the existing independent 15-minute / 2 GiB / 256-task service
caps. The Git fixture uses a real HEAD, tracked input and 30,000 identical files
to exercise ordinary index preload; no workers, runtime patches, test switches
or Git configuration were injected. Normal status remains small and useful.

`local-attempts.json` retains local results and source/log hashes. The native
files retain failed and incomplete attempts as failures: early setup/observer
issues, the single-service deadline and the untracked/unborn Git calibration
cannot count as acceptance. macOS skips do not qualify Linux-only behavior.
Raw traces, process identities, argv, environment arrays and logs are private.

The implementation is ready for TL review; full shared CI/admission/main
integration remain TL-owned. The baseline projection deliberately does not
claim pressure coverage by itself, and the pressure projection requires a
separate baseline. Neither standalone slice is final shared acceptance.

The separately documented SIGKILL of the outside cleanup owner itself before
descriptor handback remains an unqualified extended fault boundary. An
unconfirmed same-name leaf is retained as unresolved rather than swept or
reported successfully cleaned. The four actual collector-parent-loss controls
are covered; original startup waits for descriptor adoption acknowledgement.

## Installer failure privacy follow-up

The shared preparation failure path now reports only a finite installer reason,
integer exit code and a private-log reference relative to `--output`. It does not
read installer output, including oversized or invalid-UTF-8 logs. The private
`0600` log is retained; failed preparation cannot publish a completion marker.
Regression controls call actual `prepare()` and actual `main()` with owned mocked
installer failures for both installers, positive exits and signal termination.

`installer-failure-privacy.json` records exact script/test identities and isolated
local checks for this follow-up. Existing native reports qualify only their
explicit earlier runtime sources; this preparation error-path change has not
been rerun through native qualification. Prior failures and scope limitations
remain recorded. Final shared/current-main acceptance is still TL-owned.
