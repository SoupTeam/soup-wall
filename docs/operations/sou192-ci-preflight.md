# SOU-192: Ready CI preflight ordering

The Ready candidate's existing `test` (Linux), `native-macos-resilience`
(macOS), and `agent-windows-security` (Windows) jobs are the source-specific
preflight barriers. Their existing commands still compile and execute their
original suites. This change adds no runner, build, artifact, cache authority,
status context, or test substitution. The impact plan still selects the same
jobs and all five CodeQL languages; trusted SOU-91 admission still verifies
every selected job against the exact current candidate and attempt.

`components`, `agent-lifecycle-macos`, `all-features`, the four SAML target
members, Redis, PostgreSQL, and Docker now wait for the selected barriers.
An unselected barrier may be skipped; a selected barrier must conclude
`success`. A missing, failed, skipped, timed-out, or cancelled selected barrier
withholds these jobs. The run is not qualified: SOU-91 admission must continue
to reject missing or skipped required execution. Cancellation also prevents
the shared build consumers from starting after an obsolete producer completes;
their explicit producer guard still fails a non-cancelled producer failure,
and step-level `always()` uploads still retain diagnostics. Draft runs retain
fast checks and cannot use deferred execution as Ready qualification.

## Retained before-run evidence

The public [first failed #313 run](https://github.com/SoupTeam/soup-wall/actions/runs/41113625235)
at head `e93aa454c6c4d90f0a7afa436b3f1b431234b21c` started at
19:14:34 UTC on October 30. Windows Clippy failed its platform compile at
19:23:29 (8m55s from run creation). The Windows job concluded failure at
19:23:34. Its failure is retained; it was not an executed Windows test pass.

The [second failed #313 run](https://github.com/SoupTeam/soup-wall/actions/runs/41115271283)
at head `79ee47a4d8251d2a781320e274baaf6e92299e4a` started at
19:26:28 UTC. Windows Clippy and build passed; the original native test step
failed at 19:45:21 (18m53s from run creation) on the directory-frame
expectation. The Linux `test` and macOS barrier completed successfully at
19:44:38 and 19:36:52. The shared Ubuntu build producer ran
19:39:58–19:44:43, before the Windows failure. Its dependent
`linux-installed-edit` nevertheless started at 19:54:38, twenty seconds after
the replacement run was created, and was eventually cancelled at 20:01:30.
The old failed/cancelled run and the [replacement successful run](https://github.com/SoupTeam/soup-wall/actions/runs/41119019599)
at head `39670f943f1728f5f927bbaef3d21a1f87f7753d` are distinct evidence.

| Scheduling path | Old failed candidates | New failed candidate with the same selected plan |
| --- | --- | --- |
| First observable failure | Windows Clippy at 8m55s; Windows native test at 18m53s | Same original steps and failure timing, subject to runner queue variation |
| Selected expensive work | 63 deferred job records per run; 275.4 and 298.8 elapsed runner-minutes respectively, summed from public job start/end timestamps, including work before cancellation | None of those jobs starts after failed preflight; their required results remain missing/skipped and block admission |
| Obsolete shared consumers | `linux-installed-edit` started after the replacement run was created | `!cancelled()` prevents starting after run cancellation; a failed producer still reaches the fail-closed guard on an active run |

The 275.4/298.8 numbers are **observed historical elapsed job minutes**, not
billed minutes or measured savings. On an equivalent failure, they are an
upper-bound estimate of avoidable deferred work; runner queues, cancellation
timing, and job duration can change. The no-duplicate-build design adds zero
new job minutes on a healthy candidate, but moves deferred starts behind the
slowest selected barrier. On the second failed run that barrier finished
18m58s after creation. In the successful replacement run, all three barriers
were successful by 20:17:20 UTC, and the final selected job completed at
21:01:54 UTC. A healthy run may therefore have a longer wall-clock critical
path; the exact after-run latency and runner minutes require a current-source
Ready run after review. These historical runs are not qualification of this
change.

## Focused contract checks

Run `python3 -m unittest scripts.tests.test_ci_preflight
scripts.tests.test_ci_components scripts.tests.test_ci_impact -v` and
`python3 scripts/ci_components.py --check`. The preflight controls evaluate
the checked-in job conditions for Linux, macOS and Windows failures; missing,
stale, skipped, cancelled and timed-out results; Draft; docs-only and gateway
scope; and healthy Ready selection. They also require the original three
barriers, five CodeQL languages, shared producer guard, and retained
failure-artifact uploads. These are offline scheduling contracts, not a
substitute for current-source native execution or trusted admission.
