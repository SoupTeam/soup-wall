# Native launchd qualification

The [native macOS job](https://github.com/SoupTeam/soup-wall/actions/runs/39250154493/job/118051880822)
passed all 11 launchd acceptance scenarios on 2026-10-19. The entire
[CI run](https://github.com/SoupTeam/soup-wall/actions/runs/39250154493) also passed.
This is an immutable runtime checkpoint; later documentation commits or base
merges require their own final CI. These archives do not qualify untested commits.

## Exact source and artifacts

- PR head: `43dffbb450dcf1d03e49078c584876893b936075`.
- Tested merge candidate: `604d6a25ad98476a969b553d43a542dfdb4297b1`.
- Base: `030178064a368a0fb21f2e70e9da2d6705273c0c`.
- Platform: `macOS-15.7.9-arm64-arm-64bit-Mach-O`, non-root `gui/501` domain.
- Installed executable and launcher SHA-256:
  `3710d8448b3683e496f5d2edec55eb17eaf4ad8c6206f1b9640e2f64175aeb9a`.
- Plist SHA-256:
  `6387cb39e25b66b9c9058d24754a9299167fb8a2df56c29af7f97d823b40a46a`.

The executable ran from a disposable installation outside the checkout. The
unchanged artifact ZIPs contain sanitized `report.json` and collector logs,
including configuration/policy/registry/classifier digests, authenticated
instances, PIDs, timings, receiver/executor witnesses and cleanup observations.
They contain neither authentication tokens nor launchd environment dumps.

| Retained archive | SHA-256 |
| --- | --- |
| [Passing native run](native-arm64-passed.zip) | `0f1c96cec43b68950e373985d88190a94c00f6ac206dfe7a89f8ecd2b81e5838` |
| [Initial budget failure](initial-budget-failure.zip) | `66cb77fa42ebdf236b3566c93e1a162c23f6ade24839a5aa5b45267974690fc3` |
| [Bootstrap observer failure](bootstrap-observer-failure.zip) | `026f83e0747db1f8c16df3417526e404d0876ac159370322425b1df565a51812` |

## Executed controls

| Scenario | Result | Seconds |
| --- | --- | ---: |
| Install stays stopped; repeat install | Passed | 28.460 |
| Protected read, synthetic-send refusal, useful follow-up | Passed | 47.251 |
| Kill a healthy daemon and verify its replacement | Passed | 51.371 |
| Explicit stop remains stopped beyond throttle | Passed | 34.137 |
| Exhaust the real launchd restart budget | Passed | 58.551 |
| Refuse missing identity, edited/replaced files and foreign job | Passed | 23.845 |
| Refuse direct daemon, foreign PID and occupied port | Passed | 109.461 |
| Upgrade, rollback and compensate a bad replacement | Passed | 426.497 |
| Recover interrupted upgrade; preserve stopped intent | Passed | 180.685 |
| Recover partial installation/removal; repeat reinstall | Passed | 95.994 |
| Independently verify manager, processes, files and sentinels | Passed | 23.596 |

The restart budget remains three starts in 60 seconds, with a 10-second launchd
throttle. The passing control observed PID `19823` at epoch `1792412487`, PID
`20010` at `1792412497`, and PID `20201` at `1792412508`: three admissions in 21
seconds. Each was killed through the owned launchd job. The fourth launcher
exited with code zero without launching another Agent. The manager showed no
PID and `runs = 4`, unchanged after another 12 seconds. This control interrupts
the starter CLI only after bootstrap; healthy-daemon crash recovery is covered
separately by the preceding scenario.

Cleanup found no owned job, process or service artifacts. The unrelated process
remained alive, and configuration, token, audit and operator data survived
service removal. The report has no `error` or `cleanup_error`. The same job also
passed five lifecycle integration tests, seven native self-tests and six
launchd unit tests. Follow the [operator guide](../../AGENT_LAUNCHD.md) to rerun.

## Failed development evidence

The [initial native run](https://github.com/SoupTeam/soup-wall/actions/runs/39244757039/job/118033919123)
failed with `crash restart budget was not bounded`; it is not acceptance evidence.
Its restart control took approximately 176 seconds, from the preceding case's
11:37:51 UTC completion to the 11:40:47 failure. Waiting for full authenticated
readiness and repeatedly hashing the debug executable between kills allowed
the rolling 60-second window to expire. Its final manager snapshot recorded
`runs = 4` and live PID `25877`. That failed driver did not retain each inner
attempt's timestamp/PID, so the archive cannot establish a precise inner timeline.

The replacement control witnesses durable admission timestamps and manager PIDs
directly, requires all three admissions inside the actual window, and asserts
both fourth-attempt refusal and no later attempt beyond throttle. It neither
changes the configured budget nor skips the healthy-daemon crash scenario.

The [next run](https://github.com/SoupTeam/soup-wall/actions/runs/39247123254/job/118041684086)
stopped on launchctl exit `113`: an old budget was visible before the new job's
bootstrap completed. The observer now waits for the job to exist. Both failed
archives retain their failure status and report no cleanup error; neither is
counted as a pass.

This qualification covers the owned ARM64 user-session fixture. It makes no
Intel, login-autostart, system-daemon, fleet or live-model efficacy claim.

## Readiness timeout after updating the base

The [2026-10-20 native run](https://github.com/SoupTeam/soup-wall/actions/runs/39425986622/job/118638730668)
tested head `56a42bbb428c167ea2b43b7d60a0c1cbdbc415a4` as merge candidate
`2eb36e6ccc21629767f9c3f07525a9b5d1296259`. Lifecycle, self-test and service unit
tests passed, but the real launchd run stopped after `install_stays_stopped`:
the first explicit start did not verify authenticated readiness within 35
seconds. This failed run does not qualify the updated source.

The unchanged [failed report archive](startup-readiness-timeout.zip) has SHA-256
`a2a35bcde28facd195a442424ba6bbcc7f0a1b78acc145f3fa2d560cc0eed7df`.
The tested executable digest was
`170e63b036418f3871b73046740e0cb02726fbe7b15c9cc673f7312a803ecab9`.
The report contains no daemon startup milestones: failed-start cleanup had
already removed the job and process record before the driver took its snapshot.
It cannot distinguish an early launcher refusal from slow startup.

Source inspection identified repeated complete hashes of the large debug
executable in launcher ownership, managed boot and readiness verification.
The lifecycle file-digest helper now uses the already-linked native SHA-256
implementation, preserving full-byte verification and the existing hex identity.
No metadata-only cache, skipped identity check, extended readiness deadline or
relaxed restart budget is introduced. Integration tests compare known vectors,
chunk boundaries, same-length edits and the actual Agent executable against the
previous implementation. The native job retains both implementations' timings
in `lifecycle-digest.log`; a performance hypothesis alone is not acceptance.

The driver now retains timestamped admission-count, process-PID and token-file
presence observations while explicit start is running, before cleanup can erase
them. It never copies token contents, arbitrary journal fields, environment or
raw launch logs. The correction requires a new complete native run and current
source CI; the earlier passing archives remain historical checkpoints.
