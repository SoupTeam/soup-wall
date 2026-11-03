# Current installed Linux pilot: clean-user acceptance (SOU-216)

## Decision and exact source

**Accepted baseline: NO-GO for the complete lifecycle.** Run 573 passed 13/15
required observations, then the installed update entry rejected its dedicated
arguments; removal remained incomplete. Historical outcomes are never backfilled.

**Fixed author candidate: GO for the exact measured prepared-CI path.** Independent
runs [591](https://github.com/SoupTeam/soup-wall/actions/runs/41711794121) and
[592](https://github.com/SoupTeam/soup-wall/actions/runs/41711848382) each passed
all 15 required observations, including actual confirmed removal/status for both
direct and bootstrap component homes. Private before/after process provenance
and the unchanged native guard confirm complete process visibility. The path
requires an exclusively owned, empty hosted-CI user session and the namespace
prerequisite below; this is not stock-host or full-product acceptance.

Product: `62b9e69a449c0372ac5226f9e0545d888d4ea1f7`; frozen measurement driver:
`9ecc23806afc8bf22bd06dca8761c50edec6662f`. The product remains an author
candidate awaiting review, not newly accepted main. Later documentation/evidence
commits do not claim another native execution.

Earlier runs 583/584 remain genuine 14/15 NO-GO observations. Their source reports
could not identify the two inaccessible same-UID processes and emitted no removal
confirmation/apply. Subsequent pre-install diagnosis established their origin,
and ordinary-user preparation now actually terminates the empty owned user
session before installed-host use. No process is excluded from removal checks.

Accepted baseline: `9a3c5b38e56ebc6ebbeedfda98805f6a327cb371`.
[Draft PR #348](https://github.com/SoupTeam/soup-wall/pull/348) contains two
installation/recovery fixes with cause-specific regressions:

- Native `--agent-home` dispatch now reaches the dedicated update router. Baseline
  reproduction: `python3 -B scripts/pilot.py --agent-home /private/owned-home update inspect --prefix /private/owned-coordinator`.
  This read-only command reproduces the parser failure without installation or a model.
- A documented dedicated bootstrap home binds its maintenance gate to the exact
  coordinator directory identity. Every launch still verifies the selected
  managed component and selection. Entered maintenance survives A-B-A; foreign
  or replaced roots and unselected components refuse. Legacy direct markers are
  never silently enrolled into another scope.

Classifier, result-inspection and original Git implementations are unchanged.
The unchanged native removal guard must obtain complete inactivity evidence;
unknown state or unreadable same-user processes remain blockers.

## Confirmed measurement boundary

Native Ubuntu 24.04 x86_64, CPython 3.12, ordinary non-root user with zero effective
capabilities, pinned original Claude Code and filesystem/Git packages, and the
existing local scripted provider. Two independent GitHub-hosted jobs start with
empty private Agent/home/preparation state; hashed boot identity and run ID
identify each environment. No paid API calls, real secrets or private projects.

Installation uses the existing builders and source-bound component receipt.
Execution occurs outside both product and driver checkouts. Product, driver,
per-environment binary outputs, compiler inputs, profiles, policies, selections
and original child reports retain separate hashes. Equal source does not imply
bit-identical independent builds. Cache state and build durations are measured;
fully cold caches are not claimed.

The unchanged job-scoped exact-binary namespace permission is an administrator
prerequisite; see [native prerequisites](PILOT_NATIVE_PREREQUISITES.md). No global
sysctl, global AppArmor profile, setuid or product policy change is introduced.
This mode creates no OS accounts. Unassisted stock-host installation is unproven.

## Measured candidate outcomes

Both environments used ordinary UID/GID 1001 with zero effective capabilities,
native Ubuntu 24.04 x86_64 and distinct boot identities. Each passed four useful
tasks per project and both independently calibrated denied-call controls with
zero forbidden original dispatches, network connections and marker files. The
unchanged walkthrough passed 12 main plus four emergency-Stop cases. Separate
Ask smoke passed two-profile one-use redemption/replay correctness and the
existing five-second first-pending bound.

Each A-B-A sequence passed three useful reads and two paused-launch refusals
with zero host executions/provider requests. All 13 completed outer runs reported
stopped owned processes and were archived/cleaned. Both native component removals
returned retained-journal status with verified acknowledgement hashes. Project
bytes/Git state, synthetic user files, prepared selections, managed generations,
Agent executables and maintenance history survived removal. Product source/tree
matched before and after the complete lifecycle in both environments.

| Run | Native Agent source build | Catalog / ledger preparation | Eight useful task wall times | First pending, filesystem / Git | Archived + cleaned runs | Required inventory |
| --- | --- | --- | --- | --- | --- | --- |
| 591 | 149.288 s | 24.780 / 24.521 s | 21.962–22.273 s | 1007.8 / 990.0 ms | 13/13 | 15/15 passed |
| 592 | 188.722 s | 31.905 / 31.146 s | 28.193–29.528 s | 1409.0 / 1389.1 ms | 13/13 | 15/15 passed |

These durations describe separate phases, not human onboarding or per-tool
percentiles. General useful-task/installation latency thresholds remain
unapproved. Equal source does not imply bit-identical independent native builds;
exact per-environment outputs are retained.

[Evidence metadata index](evidence/sou-216-acceptance/summary.json) retains all
17 complete-lifecycle attempts with original statuses, independent expectation
verification, source/input/profile/policy hashes, timings, cleanup, archive and
removal outcomes. Original report contracts remain in the linked Actions artifacts.
The earlier NO-GO failure paths omit their final whole-source snapshot; those
missing observations are not backfilled by the successful new measurements.

## Process visibility and owned CI session preparation

Read-only pre-install [probe 585](https://github.com/SoupTeam/soup-wall/actions/runs/41705360233)
identified the inaccessible processes as the existing `systemd --user` manager
and its `(sd-pam)` child, both predating pilot execution. Private observations
retain PID/start/parent, all UID values, capabilities, tracing, dumpability when
reported, namespace and cgroup evidence. Raw argv/environment contents are never
collected. [Probe 588](https://github.com/SoupTeam/soup-wall/actions/runs/41709392593)
confirmed their normal termination and complete same-UID visibility afterwards.

The preparation helper is restricted to owned disposable GitHub-hosted Ubuntu
24.04 x86_64 jobs, ordinary UID and zero effective capabilities. It matches the
system manager's read-only `user@UID.service` identity to the kernel process
identities and exact cgroup cohort. The cohort must contain only that manager
and its PAM child, must exclude the runner/driver ancestry, and must have no
tracing, other active scopes, working service processes, non-vendor units or
pending jobs. Unknown or changed evidence refuses before any exit request.

Only then does the helper request the documented
[`systemctl --user exit`](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)
operation. It waits for those exact identities to terminate and independently
requires all same-UID process evidence to be available. UID, capabilities,
namespaces, caller cgroup, ptrace settings and AppArmor context remain unchanged.
This helper uses no sudo, PID/group kill, force flag, account creation, system-wide service reconfiguration or
global settings change, or ignored process. This preparation is not a personal
workstation cleanup command; the helper refuses outside its disposable-CI scope.

The native product/removal implementation remains pinned and unchanged. Every
preview and apply still performs the original complete process/run checks; a
session preparation report never authorizes removal. The workload records
visibility before installed-host execution and after completed-run cleanup.
A separate read-only step records private provenance after the full attempt and
cannot enable quiescence. Standard CMS AES-256-GCM envelopes retain the bounded
private snapshots; only the public recipient certificate is versioned. The
private key and decrypted records remain outside Git. Artifact/ciphertext/plaintext
hashes and authenticated decryption results are retained in the
[diagnostic metadata index](evidence/sou-216-acceptance/process-diagnostics.json).
Original raw run archives and removal journals remain private in the disposable
job until teardown, while their outcome/hash evidence is preserved.

This adds a measured environment prerequisite: a quiescent, exclusively owned CI
user session. It does not establish complete lifecycle acceptance for an active
personal desktop or an arbitrary host with unreadable processes.

## Reproduce

Check out frozen driver `9ecc23806afc8bf22bd06dca8761c50edec6662f` in a clean
measurement checkout. Use the existing
[installed producer](PILOT_INSTALLED_FRONT_DOOR.md). Supply inputs emitted by the
pinned native builders and retain the original build receipt. In the owned hosted
CI job, after acquisition/build and before the installed-host workload, prepare
complete process visibility using the CI-only helper:

```sh
SOUP_CI_RUNNER_ENVIRONMENT=github-hosted \
  python3 -I -B scripts/ci_pilot_user_session.py --quiesce
export SOU216_CI_USER_SESSION_REPORT="$RUNNER_TEMP/sou216-user-session/report.json"
```

Supply the actual builder-output paths for the producer command:

```sh
python3 -B scripts/qualify-installed-front-door.py --run --clean-user-only \
  --runtime-source /absolute/pinned-product-source \
  --source-build-receipt /private/agent-build/generations/ID/receipt.json \
  --expected-commit 9ecc23806afc8bf22bd06dca8761c50edec6662f \
  --output /private/new-clean-user-result \
  --component-python /usr/bin/python3.12 --strace /usr/bin/strace \
  --agentfw /private/agent-build/generations/ID/bin/agentfw \
  --git-launcher /private/agent-build/generations/ID/bin/git_launcher \
  --sandbox-tests /private/agent-build/generations/ID/bin/sandbox_tests \
  --git /private/native/git --bwrap /approved/exact/bubblewrap \
  --node-archive /private/assets/node.tar.xz \
  --claude /private/assets/claude/node_modules/@anthropic-ai/claude-code-linux-x64/claude \
  --python /usr/bin/python3.12 --allow-download
```

After the installed-host attempt, including failures, collect read-only private
provenance without any session-exit operation:

```sh
SOUP_CI_RUNNER_ENVIRONMENT=github-hosted \
  python3 -I -B scripts/ci_pilot_user_session.py --after-cleanup
```

The existing `mcp-real-filesystem.yml` workflow automates these steps with the explicit
`installed_focus=clean-user`, `native_preparation_only=true` selection. Leave
every other flag false, optional comparison inputs empty and stability off.
Dispatch twice at the same driver commit for two fresh environments. Acquisition
and compilation precede installed execution; no protected server downloads its
own implementation at startup. Only pinned public inputs and owned synthetic
projects are used.

## Fixed useful work and independent witnesses

Both environments use two new projects, distinct from historical SOU-145 inputs:

| Project | Fixed developer tasks |
| --- | --- |
| Catalog service | Read the API contract exactly; inspect the complete pending configuration diff; trace both local commits; inspect the latest commit |
| Release ledger | Read the release-review contract exactly; inspect the complete pending retention diff; trace both local commits; inspect the latest commit |

Each project’s expected source bytes, Git commit IDs, messages and complete
pending diff are recorded before that project’s first provider/host execution. Each task uses the genuine
pinned host and original servers through `agentfw pilot`, outside both source
checkouts. Error flags, missing/partial replies and unconfirmed process cleanup
cannot count as useful work. A failed useful task remains in its four-task
denominator; later independent tasks proceed only after confirmed cleanup.

Denied original writes/resets and an unavailable host shell have independent
original-dispatch, receiver, marker-file and complete source/index/object
preservation witnesses, followed by a useful read. The receiver is positively
calibrated first. An unsupported tool or profile refusal is not relabeled a
native policy Deny.

The unchanged [quickstart walkthrough](PILOT_QUICKSTART.md) runs its complete
inventory on a separately generated demo selection: useful operations, Ask,
cancellation, timeout, daemon loss, fresh recovery and cleanup. The accepted
two-profile Ask approval smoke additionally checks exact inspection, one-use
redemption, replay rejection and independent effects. Its two-case correctness
scope is not the full fifteen-case Ask inventory or performance acceptance.
Original child reports retain their formats and hashes.

The current `agentfw pilot update` controller selects two independently prepared
generations of the same pinned product/binary set through the documented separate
retained bootstrap Agent. Its installed copy is hash-verified against the native
builder output. Useful original reads must succeed before update, after update
and after rollback. Entered maintenance must independently refuse host execution
and provider requests after both transitions, until a fresh confirmed leave. This measures coordinated
selection recovery, not a binary-version upgrade. An additional identity-only
synthetic component update checks stale-selection refusal and component rollback.
Removal uses built-in `agentfw pilot-removal preview/apply/status` for both direct
and bootstrap component homes, explicit confirmation/consent and retained recovery
journals/acknowledgements. Its exact
receipt-owned component scope retains Agent executables, prepared generations,
coordinator state, audit/history and recovery records by design. New project
bytes, Git state, prepared selections and synthetic user files must survive. No classifier,
result-inspection or original Git implementation is changed here. Failures in
those owned areas retain exact task/tool/result hashes and reproduce against the
fixed accepted source for SOU-97/157/177.

## Bounds and report interpretation

The existing host, broker, pending-call and walkthrough limits are unchanged.
Task wall time includes host startup and cleanup; it is not a per-tool p95.
The existing five-second first-pending correctness observation is reused.
General useful-task/installation latency thresholds remain **unapproved**.

`report.json` reuses `sw-installed-front-door-qualification/1`. Its separate
`clean_user` inventory records every attempted, failed and incomplete case;
ordinary installed producers and SOU-145/176/190 contracts are not replaced or
backfilled. Child walkthrough/Ask reports are retained separately. Raw syscall
traces stay private; bounded summaries include hashes and independent witnesses.

GO can cover only the exact measured, preprovisioned read-only path. Any failed
or incomplete required observation is NO-GO for this scope. Scripted-provider
results are not live-model attack efficacy, novice-human evidence, WSL evidence,
license/advisory clearance, public release or full-product acceptance.

## All attempts and reproducible defects

The linked Actions artifacts retain the original report contracts and all
failed/incomplete observations. The accompanying metadata index records exact
artifact and original-report hashes; it is a projection, not another grader or
replacement report contract. No canceled attempt contributes success evidence.

| Run | Required observations | Outcome / correction |
| --- | --- | --- |
| [571](https://github.com/SoupTeam/soup-wall/actions/runs/41645623208), [572](https://github.com/SoupTeam/soup-wall/actions/runs/41646339891) | Each 5 passed, 10 incomplete | Denied-call observer refused abbreviated collector arguments; driver switched to the accepted full capture bound, with a truncation regression. |
| [573](https://github.com/SoupTeam/soup-wall/actions/runs/41649571638) | 13 passed, 2 incomplete | Baseline installed update produced no JSON because native `--agent-home` bypassed the dedicated router; product routing fixed. |
| [574](https://github.com/SoupTeam/soup-wall/actions/runs/41649814940) | Canceled before application report | Superseded after baseline reproduction. |
| [575](https://github.com/SoupTeam/soup-wall/actions/runs/41650804844) | 13 passed, 1 failed, 1 incomplete | Exact selected binary paths in the long-lived harness argv triggered the unchanged inactivity guard. Driver now execs through a private anonymous argument FD, closed before execution; a native regression still refuses genuine selected-path argv. |
| [576](https://github.com/SoupTeam/soup-wall/actions/runs/41651856544), [577](https://github.com/SoupTeam/soup-wall/actions/runs/41652164981) | Canceled: 10/9 passed, 5/6 incomplete | Superseded by the corrected argument handoff; incomplete inventory retained. |
| [579](https://github.com/SoupTeam/soup-wall/actions/runs/41655608365), [580](https://github.com/SoupTeam/soup-wall/actions/runs/41655905813) | Each 13 passed, 1 failed, 1 incomplete | `maintenance_scope_changed` on the first coordinated useful run; added the documented separate bootstrap and identity-pinned coordinated maintenance integration. |
| [581](https://github.com/SoupTeam/soup-wall/actions/runs/41664166977), [582](https://github.com/SoupTeam/soup-wall/actions/runs/41665051216) | Each 14 passed, 1 failed | A-B-A and paused-launch refusals passed. Removal preview reported unverified retained read-only runs and unavailable process evidence; no removal applied. Driver now uses accepted archival and records bounded process diagnostics. |
| [583](https://github.com/SoupTeam/soup-wall/actions/runs/41671867237), [584](https://github.com/SoupTeam/soup-wall/actions/runs/41672949388) | Each 14 passed, 1 failed | All 13 completed runs archived/cleaned. Three fresh previews each refused solely on unavailable process evidence; two persistent same-UID `cwd` EACCES observations per environment. No apply or bootstrap removal/status. |
| [585](https://github.com/SoupTeam/soup-wall/actions/runs/41705360233) | Diagnosis only | Identified the existing systemd user manager and sd-pam before any pilot execution. |
| [586](https://github.com/SoupTeam/soup-wall/actions/runs/41708018868), [587](https://github.com/SoupTeam/soup-wall/actions/runs/41708695515) | Failed preparation diagnostics | Catalog/parser refusals before any exit request; bounded private provenance retained. Empty systemctl unit/job responses now use strict documented text parsing. |
| [588](https://github.com/SoupTeam/soup-wall/actions/runs/41709392593) | Preparation only, passed | Exact empty user-session cohort terminated through the user API; complete visibility and unchanged security context verified. No application acceptance claim. |
| [589](https://github.com/SoupTeam/soup-wall/actions/runs/41710501051), [590](https://github.com/SoupTeam/soup-wall/actions/runs/41710580902) | Canceled: each 6 passed, 9 incomplete | Superseded to add encrypted post-cleanup provenance; original incomplete outcomes retained. |
| [591](https://github.com/SoupTeam/soup-wall/actions/runs/41711794121), [592](https://github.com/SoupTeam/soup-wall/actions/runs/41711848382) | Each 15/15 passed | Complete native lifecycle, original removal preview/apply/status for two homes, preserved user data and authenticated before/after private provenance. |

Earlier fully instrumented useful-task timings are not a performance baseline for
later ordinary launches. The two denied-call controls retain full syscall capture.

The corrected removal sequence enters maintenance for both homes, then uses the
existing [completed-run archival](completed-run-archival.md) preview/archive/apply
protocol on every completed read-only run. Archive bytes and recovery journals
remain in the disposable job’s private output until runner teardown; published
evidence retains their hashes/outcomes, not the raw archives or acknowledgement
values. Preservation assertions describe the measured removal boundary, not
permanent storage after the disposable environment is destroyed. Unknown/incomplete
state is never purged. At most three fresh read-only native previews may observe
a transient process-only refusal; each attempt is retained. Apply requires a
fully clear fresh preview and repeats the original guard. Persistent uncertainty
is NO-GO, including when the relationship of unreadable same-user processes is unknown.

## Development verification and handoff

Focused local suites: 112 tests, 101 passed and 11 platform/environment skips.
Mandatory native pin checks additionally exercise Linux process refusal and
maintenance/current-generation controls. Source workflow actionlint, generated
workflow consistency and local documentation links pass. Local checks do not
establish native acceptance. The measured driver’s Draft fast checks, admission
and all five CodeQL analyses are checked separately from native acceptance. Both
new native qualification workflows passed; earlier failed/NO-GO reports retain
their original results.

PR stays Draft. Final shared Ready qualification, review/admission and merge
remain TL-owned. Checkpoint: November 4; delivery deadline: November 5, 2026.
