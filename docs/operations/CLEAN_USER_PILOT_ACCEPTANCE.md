# Current installed Linux pilot: clean-user acceptance (SOU-216)

## Decision and exact source

**Accepted baseline: NO-GO for the complete lifecycle.** Run 573 passed 13/15
required observations, then the installed update entry rejected its dedicated
arguments; removal remained incomplete. Historical outcomes are never backfilled.

**Fixed author candidate: NO-GO for the complete lifecycle.** Independent runs
[583](https://github.com/SoupTeam/soup-wall/actions/runs/41671867237) and
[584](https://github.com/SoupTeam/soup-wall/actions/runs/41672949388) each passed
14/15 required observations. All useful work, interruption/recovery, Ask/replay,
A-B-A and completed-run archival passed. Native removal preview still refused:
`process_evidence_unavailable_or_inconsistent`. In each environment, two same-UID
processes returned `EACCES` while reading `cwd`, with the same hashed identities
persisting through all three previews. Their origin/relationship to the pilot
was not established; they are not assumed unrelated or safely inactive. No
confirmation was emitted, no removal applied, and bootstrap removal/status
remained unattempted. This is a genuine unresolved process-visibility blocker,
not a passing uninstall or complete lifecycle acceptance.

Product: `62b9e69a449c0372ac5226f9e0545d888d4ea1f7`; measurement driver:
`4b7209908d9be08b2bcdce2ebba2956686f336a7`. The product awaits review and is not
newly accepted main. Later evidence/documentation commits do not claim a new
native execution. The supported measured prefix is installation through useful
work, recovery and archival under the prerequisites below. Complete removal
requires fresh qualification with fully available same-UID process evidence;
its original guard must remain intact. No safe in-scope product correction for
the inaccessible processes was established, and no privileges, force-stop,
process exclusions or security relaxation were introduced.

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

Both runs used UID/GID 1001, effective capabilities 0, Ubuntu 24.04 x86_64 and
runner image `20261026.354.1`, with distinct hashed boot identities. Each completed
four tasks per project and two independently calibrated denied-call controls;
forbidden original dispatches, network connections and marker files were zero.
The unchanged walkthrough passed 12 main cases plus four emergency-Stop cases;
the separate two-profile Ask smoke passed one-use redemption/replay controls.
A-B-A passed three useful reads and two paused-launch refusals with zero host
executions/provider requests. All 13 completed outer runs reported stopped owned
processes. Project bytes and Git/index/object state matched their pre-run
snapshots after the full lifecycle through update/rollback.

| Run | Native Agent source build | Catalog / ledger preparation | Eight useful task wall times | First pending, filesystem / Git | Archived + cleaned runs | Required inventory |
| --- | --- | --- | --- | --- | --- | --- |
| 583 | 200.016 s | 33.071 / 32.765 s | 27.656–28.997 s | 1302.5 / 1315.4 ms | 13/13 | 14 passed, 1 failed |
| 584 | 201.597 s | 32.177 / 31.954 s | 29.388–29.744 s | 1169.4 / 1181.4 ms | 13/13 | 14 passed, 1 failed |

Build/preparation/task times cover different phases, not total human onboarding
or a per-tool percentile. Both first-pending observations met the existing
5000 ms correctness bound. All other installation/useful-task latency thresholds
remain unapproved. Independent builds have per-environment output hashes;
bit-identical reproduction is not claimed.

[Evidence metadata index](evidence/sou-216-acceptance/summary.json) retains every
attempt, frozen expectation verification, original artifact/report digests,
source/input/profile/policy hashes, timings, cleanup, archive outcomes and all
removal preview observations. Original reports remain in their linked Actions
artifacts. The failure path exits before the final whole-source snapshot;
initial source/tree and build receipt identities and post-lifecycle project
snapshots remain available. No final whole-source preservation claim is made.

## Reproduce

From a clean measurement-driver checkout, use the existing
[installed producer](PILOT_INSTALLED_FRONT_DOOR.md). Supply inputs emitted by the
pinned native builders and retain the original build receipt:

```sh
python3 -B scripts/qualify-installed-front-door.py --run --clean-user-only \
  --runtime-source /absolute/pinned-product-source \
  --source-build-receipt /private/agent-build/generations/ID/receipt.json \
  --expected-commit FULL_MEASUREMENT_DRIVER_COMMIT \
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

The existing `mcp-real-filesystem.yml` workflow adds the explicit
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

Expected source bytes, Git commit IDs, messages and complete pending diffs are
recorded before any provider or host is started. Each task uses the genuine
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

Focused local suites: 101 tests, 90 passed and 11 platform/environment skips.
Mandatory native pin checks additionally exercise Linux process refusal and
maintenance/current-generation controls. Source workflow actionlint, generated
workflow consistency and local documentation links pass. Local checks do not
establish native acceptance. The measured driver’s Draft fast checks, admission
and all five CodeQL analyses passed; both native qualification workflows correctly
remain failed/NO-GO at strict removal preview.

PR stays Draft. Final shared Ready qualification, review/admission and merge
remain TL-owned. Checkpoint: November 4; delivery deadline: November 5, 2026.
