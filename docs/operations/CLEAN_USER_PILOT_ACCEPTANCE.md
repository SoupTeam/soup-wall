# Current installed Linux pilot: clean-user acceptance (SOU-216)

## Selected path and current decision

**Accepted baseline: NO-GO for the complete lifecycle.** Native run 573 completed
13 of 15 required observations: all eight useful tasks, both denied-call controls,
the unchanged 12-case walkthrough, component install and two-profile Ask/replay
smoke passed. Installed coordinated update then failed before its JSON preview;
removal remained unattempted. This matches the independently reproduced routing
defect below. Original failed/incomplete outcomes remain retained.

**Fixed author candidate: final two-environment measurements pending.** No
first-use, performance or product GO follows from local Python checks. The
checkpoint is November 4 and delivery deadline is November 5, 2026.

The accepted baseline is `9a3c5b38e56ebc6ebbeedfda98805f6a327cb371`. The first clean-user attempts
use that exact product. Inspection also reproduced an installed update defect:
the native entry prepends `--agent-home`, but the update router only recognized
`update` as argv[0], so its dedicated options fell through to an ordinary parser
and were rejected before update preview. Reproduce on the accepted source with
`python3 -B scripts/pilot.py --agent-home /private/owned-home update inspect
--prefix /private/owned-coordinator` (one command). This read-only failure does
not require a model or installation.

Product candidate `62b9e69a449c0372ac5226f9e0545d888d4ea1f7` includes the
routing fix first recorded in `75875f16dfbc19503feb22fe6871116cf6bd7618` and a
coordinated-maintenance integration fix. A dedicated retained bootstrap home
owns a stable gate bound to the exact coordinator directory identity. Every
launch still verifies the currently selected managed component and selection;
maintenance remains entered across generation update/rollback. Different or
replaced coordinators and unselected components refuse, and legacy direct-home
markers are never silently re-enrolled. Cause-specific regressions cover these
controls. This is an **author candidate awaiting review**, not newly accepted main.

Fresh runs pin this product in a separate clean checkout. The existing native
builders and component builder bind its source and selected outputs; the newer
measurement-driver SHA remains separate. Both environments use the same source
and locked upstream/tool inputs, with exact independently built binary outputs
recorded per environment. This does not claim bit-identical reproducible builds.
Driver, product, binary, profile, policy, selection and original child-report
identities are recorded independently.

Supported measurement path: native Ubuntu 24.04 x86_64, ordinary non-root user
with no effective capabilities, CPython 3.12 and the current pinned original
Claude Code, filesystem and Git packages. Two separately dispatched GitHub-hosted
jobs provide fresh disposable user environments; each starts with empty private
Agent/home/preparation state. Run ID and hashed kernel boot identity distinguish
the environments. Cache state and build durations are observations; this is not
a claim that every compiler/download cache was cold.

Ubuntu's namespace permission is an explicit administrator prerequisite. This
uses the unchanged job-scoped exact-binary provisioning procedure documented in
[native prerequisites](PILOT_NATIVE_PREREQUISITES.md). It changes no global sysctl,
global AppArmor profile, setuid bit or product policy. The new measurement mode
does not run the older isolated-account cleanup fixture or create OS accounts.
A successful run cannot establish unassisted stock-host installation.

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

## Preserved initial attempts

Runs [571](https://github.com/SoupTeam/soup-wall/actions/runs/41645623208) and
[572](https://github.com/SoupTeam/soup-wall/actions/runs/41646339891) used driver
`fdfd0a85f69b52ea48c3c064c475df54234f6723`. They failed at the first denied-call
observer after the catalog project's four useful tasks succeeded. Later cases
remain incomplete, not skipped successes. Run 571 retained artifact digest
`d03af541caae27de1bc958be8b9229a9c9cb75d7d1c627b5576b972e3991781a`.
The initial diagnostic capture used a 2048-byte strace string cap; the next driver
uses the accepted full argument-string bound and preserves finite observer
refusal codes. A regression rejects abbreviated installed collector arguments.
No product policy/classifier was relaxed. Final measured outcomes remain pending.

Run [573](https://github.com/SoupTeam/soup-wall/actions/runs/41649571638) used
driver `90226b6facdadf34621c4070863ef3c9bf21976f` and the unchanged accepted
product. Both denied-call observers passed after complete capture was selected.
The original report ends with `JSONDecodeError` in `update-rollback` (the
installed update parser emitted no JSON); required removal remains incomplete.
Artifact digest: `3e0903a6dc1301615e82a3a4d2e5433b7d3a9005269886e17d7c673160d57bac`.
Run [574](https://github.com/SoupTeam/soup-wall/actions/runs/41649814940) was
explicitly canceled as superseded after the baseline routing defect was
reproduced. It contributes no success evidence.

Run [575](https://github.com/SoupTeam/soup-wall/actions/runs/41650804844) used
product candidate `75875f16dfbc19503feb22fe6871116cf6bd7618` and driver
`90efca5f2275cb6e3a794263d5db4e91c9b7758e`: 13 required cases passed, update
failed with `operator_refused:active_or_uncertain_pilot_run`, removal remained
incomplete. Artifact digest:
`9ea1f3608e5adc850be7bf65e6620957be61b2a4ea908ff687abd7e6386cdb07`.
The unchanged inactivity guard treats an exact selected binary path anywhere in
a same-user argv as active/uncertain evidence. The long-lived qualification
parent itself carried the selected role paths. The driver now execs its isolated
entry using a private anonymous argument descriptor, then closes that descriptor
before qualification. The guard is unchanged; a native regression still requires
it to refuse a real process carrying the selected path. Runs 576/577 were canceled
as superseded and retain their incomplete observations.

Useful-task timings in the new driver use ordinary installed launches. Full
syscall capture remains on both denied-call controls. Earlier instrumented
attempts are not a performance baseline or optimization claim.

Runs [579](https://github.com/SoupTeam/soup-wall/actions/runs/41655608365) and
[580](https://github.com/SoupTeam/soup-wall/actions/runs/41655905813) used driver
`2c74e609e2dcdf963d8549c385136f50a7d3ff58` and routing-only product candidate
`75875f16dfbc19503feb22fe6871116cf6bd7618`. Each passed 13 required observations,
then failed the first coordinated useful run with `maintenance_scope_changed`;
update/rollback and removal stayed failed/incomplete. All observed processes had
stopped. Their artifact digests are respectively
`0bb5061b8f70d4ab19c2dbfb08dc32690012f17ec04cedd9bca58b371bd86736` and
`02c5f4732ba5cf50ee003fb5be02490dfe507ba47371eb5ff1a85406e693ce6f`.
The driver now uses the documented dedicated bootstrap, and the product candidate
adds a stable, identity-pinned coordinator gate with full current-generation
revalidation. A legacy direct installation remains a separate scope. Native
qualification of this candidate remains pending.

Runs [581](https://github.com/SoupTeam/soup-wall/actions/runs/41664166977) and
[582](https://github.com/SoupTeam/soup-wall/actions/runs/41665051216) used product
`62b9e69a449c0372ac5226f9e0545d888d4ea1f7` and driver
`be5e99b79211455af3b3d37cf54c49dd9010fb7a`. Both completed 14/15 required cases,
including useful A-B-A runs and independent zero-host/provider maintenance
refusals across update and rollback. Removal preview blocked on
`active_or_unverified_retained_run` and
`process_evidence_unavailable_or_inconsistent`; no removal was attempted.
Artifact digests: `bc3eba9a4498597aa51369428e198dbc2ae8232fb131682dc0558026b5505e19`
and `fe95e9d04a48238707716b3e984582462683993298e482790aec73d20194a7ee`.

Before component removal, the corrected sequence now enters maintenance for both
installation homes and uses the existing [completed-run archival](completed-run-archival.md)
preview/archive/apply protocol on every completed read-only run. Exact private
archives, their hashes and outcome records are retained. Unknown/incomplete state
is never purged. Removal still uses its original process-evidence requirements;
read-only diagnostics record finite failure stages, and at most three fresh
previews may observe a transient process-only refusal. Every such observation
remains in the report. Only a fully clear fresh native preview can be applied;
persistent uncertainty remains NO-GO.
