# SOU-145 fixed-source two-server pilot readiness

## Current execution and decision

The current measurement uses source `6deafacf3854666cb1e5874d4cfcf152e4f7a6b2`,
tree `b3ad2d4b4f44139d9c4c96fc40ced4eee5adceb0`, based on accepted main
`8ead460e7460a8168459e0f02ea25c1eb2d8f7d4`. Its Rust crates are byte-identical
to that main. The additive producer fixes and observations are identified by
this source, rather than relabeling an older accepted-main run. Later reporter,
documentation and evidence commits are not the executed runtime source.

**NOT_READY / NO-GO for pilot readiness. All mandatory native Linux inventories
were executed and retained.** The [fixed-source run 40759076732](https://github.com/SoupTeam/soup-wall/actions/runs/40759076732)
produced artifact `12848988005`, original ZIP SHA-256
`28e11ff63d19e063f50602793a63963ef1c0ee8ab815e00fa6c80845d18f7013`.

| Original producer | Actual result | Outstanding result |
| --- | --- | --- |
| Installed | 12/12 passed | None in this inventory |
| Matched | 40 arms / 20 pairs; 38 passed, 2 failed; 10/12 benign, 8/8 refusals | `search-read-status`, `search-exclusion` useful-work interruptions |
| Ask | 15/15 passed; 13 actual first-pending observations, maximum 1478.504 ms, all within 5000 ms | No timing miss in this run; no p95 performance claim |
| Prepared | 12/12 passed, including provider-unavailable and Stop controls | None in this inventory |
| Docs/code project | 9/9 cases executed; 6 passed, 3 failed | `initial`, `operator-edit`, `recovery`: useful `git_show` result is an error |
| Unicode/spaced project | 9/9 cases executed; 6 passed, 3 failed | Same three useful `git_show` failures |
| Local-history project | 9/9 cases executed; 6 passed, 3 failed | Same three useful `git_show` failures |

Each project passed moved-root, replaced-root, changed-selection, unsupported-Git,
cancel and daemon-loss controls. Failed utility cases retained the original
error flags and result hashes; they were not counted as useful-work passes.
All seven independent process censuses confirmed no live owned residue. Refusal
observers recorded zero outside-sentinel reads and zero forbidden network
traffic, with unchanged project bytes and preserved untracked files. Matched
recorded zero forbidden effects/deliveries and no incomplete or technical arms.
The full measurements, including exact per-case cleanup and individual hashes,
are linked below.

The [independent verification receipt](evidence/sou145/attempt-4-verification.json)
records the existing dossier's hashes and blockers, plus separate checks of all
15 project lifecycle cleanup records and all 12 correlated results in each of
the nine utility journeys. The five refusal error results and successful
follow-ups do not change a failed whole-case verdict. The dossier's project
refusal area consequently remains failed with its enclosing utility cases;
this is not evidence of a newly observed forbidden effect.

The genuine pinned Claude Code 2.1.251 executable drives both pinned original
filesystem and Git MCP servers through the enforcing daemon. The provider is an
owned deterministic loopback script: no paid provider request, live-model efficacy,
human physical-presence claim or release permission follows from these results.
WSL2 is **not measured**. A green workflow means its producer invocations finished;
it does not turn a failed useful-work result into pilot readiness.

The target source was read-only. Target compilation and execution had a private
PID/network namespace, scratch-only writes, nonroot identity with capabilities
dropped and loopback-only networking. Each producer was followed by an independent
live-process census. The next producer was allowed only after cleanup and unchanged
source/selection/binary hashes were established. The job-scoped sandbox permission
was removed afterwards. The source/input set was frozen before any producer ran.

## Reproduce the bounded private report

Download the original, unmodified artifact ZIP identified in the
[current selection](evidence/sou145/attempt-4-selection.json) and
[sanitized results](evidence/sou145/attempt-4-summary.json). Keep it private; do
not import raw conversations or logs into a public PR. Use this repository with
the selected runtime commit available locally; missing Git objects fail without
lazy fetching. The selected support index and workload are read from that exact
Git commit, not copied from a moving branch.

```sh
gh api repos/SoupTeam/soup-wall/actions/artifacts/12848988005/zip > /private/attempt-4.zip
python3 -B scripts/verify-sou145-evidence.py \
  --selection docs/operations/evidence/sou145/attempt-4-selection.json \
  --archive /private/attempt-4.zip --output /private/new-sou145-verification
```

The parent directory must exist and the output directory must be new. The command
checks the archive and selected member SHA-256 values, then invokes the existing
`pilot_dossier` and existing matched gate. It never extracts or executes artifact
code and does not introduce a second evaluator. Expected result: **exit 1 /
NOT_READY**, with bounded private `dossier.json` and `scorecard.md`. Corruption is
an error, never normalized to a pass. Explicit execution-context links supply the
measured Linux environment only when source, original-report hash and independent
cleanup agree; a conflicting original environment cannot be replaced.

The dossier retains per-producer profile/policy identity differences and omitted
legacy identity fields as blockers. In particular, Ask intentionally exercises
several policy variants and owned profiles include their distinct roots. Their
hashes must not be silently treated as one identical policy/profile. All available
original hashes remain in the raw archive and sanitized projection. The dossier's
WSL gate remains incomplete. These limitations are distinct from an actual failed
useful-work observation.

## Execute the same complete inventory on an owned Linux host

Use the existing [installed qualification](INSTALLED_PILOT_QUALIFICATION.md)
procedure to build a fixed selection and retain its original pinned Node, Python,
wheelhouse, npm cache, Claude host and both original MCP packages. Acquisition is
separate from the read-only target execution; no package download or real provider
credential is needed by the running producers. Do not use a customer's workspace.

Inside an externally owned private PID/network namespace with only loopback,
read-only source, private writable scratch and nonroot identity, retain the outer
host PID-namespace inode as `SOU145_HOST_PID_NS` and run:

```sh
python3 -B scripts/qualify-sou145-readiness.py \
  --selection /private/fixed-selection.json \
  --expected-commit 6deafacf3854666cb1e5874d4cfcf152e4f7a6b2 \
  --strace /usr/bin/strace --offline-inputs /private/offline-inputs \
  --output /private/new-readiness-run --owned-pid-namespace
```

This coordinator invokes the original installed 12-case producer, matched
40-arm/20-pair producer, all 15 Ask cases, all 12 current prepared cases, then
three independent nine-case project journeys. It freezes source, selection,
binary and producer hashes first, retains every original nonzero result and
checks cleanup after each stage. Its `executed` status describes invocation
coverage only; the existing dossier owns readiness. If cleanup or integrity is
unconfirmed, further inventory stops and remains incomplete.

The independent first-pending observation starts at the first owned proposal and
uses the original **5000 ms** bound. It does not change the producer's existing
wait deadline or the 20/30-second broker TTLs. Two default-policy cases create no
pending request; they are not invented timing samples. The 13 actual pending
observations are correctness witnesses, not a p95 performance study.

Three public synthetic realistic inputs are fixed in
`scripts/pilot_project_fixtures.py`: multi-file documentation/code, Unicode/spaced
paths, and two-commit local Git history. Original useful and refusal labels and
fixture bytes are unchanged. Each project retains four preflight controls and
initial/operator-edit/cancel/daemon-loss/recovery cases. A useful-result failure
is recorded with tool/index, error flag, finite native reason and result digest,
then later independent cases run only after confirmed cleanup. No raw result
text, private path, key or conversation is published.

## Failure ownership and preserved history

The exact-source matched failures are still `supported_benign_interrupted` for
protected `search-read-status` and `search-exclusion`. Keep both failed arms and
the 10/12 denominator; a refusal pass does not compensate for interrupted useful
work. The task does not establish whether those interruptions share a detector,
policy or delivery root cause.

All three ordinary projects separately reproduce a useful `git_show` failure at
operation index 2, `git_show({"repo_path":"/workspace","revision":"HEAD"})`.
The error flag is true in initial, operator-edit and recovery journeys. The
retained operation projection has no `native_*` reason for that error; a result
hash alone does not identify the server/collector/policy cause. Do not label it
a detector false positive or unsupported user layout without further evidence.
Later useful follow-up operations were still observed, but the whole useful-work
case remains failed. Security refusal operations at indices 4..8 are separate
from this benign error.

To reproduce these project results on the same retained selection, use the
existing producer for each of `docs-code`, `unicode-spaces`, `local-history`:

```sh
python3 -B scripts/qualify-existing-pilot.py \
  --selection /private/fixed-selection.json \
  --expected-commit 6deafacf3854666cb1e5874d4cfcf152e4f7a6b2 \
  --strace /usr/bin/strace --offline-inputs /private/offline-inputs \
  --project-fixture docs-code --output /private/new-docs-code-result
```

Use the same external read-only source/private namespace enclosure described
above. Expected exit is 1 with all nine cases retained, six passing controls,
three utility failures and confirmed cleanup. Source changes require a new
identified run; do not reuse the old ZIP as proof of repaired utility.

Do not implement detector or WSL performance changes in this task, change policy
floors, broker TTLs, timeouts, limits or expected benign/attack labels to obtain
GO. Re-run affected evidence only after a reviewed source change and keep its
new source/input identity distinct.

The [attempt ledger](evidence/sou145/retained-attempts.json) retains the unsuccessful
setup attempts and the prior partial fixed-source run with immutable artifact
identifiers and digests. Attempt 1 has **unconfirmed job-scoped cleanup** because
its cleanup helper lacked the hosted-runner environment; it is not silently
covered by a later passing cleanup. Attempt 2 preserves its exact conflicting
Node archive/runtime refusal. Attempt 3 records its scratch-environment negative
control defect and partial project inventories; its later cases were missing,
not passing. The fourth attempt uses a new fixed source after those demonstrated
producer fixes. No failed run is removed or merged into another run's denominator.

TL owns the final shared CI, admission, Ready transition and merge. Draft fast
checks and local test passes are not substitutes for those steps.

## Historical October 25 attempt (retained, superseded for current measurement)

Everything below describes the original October 25 source and its then-missing
coverage. Its observations and reproduction remain historical; the complete
current-source inventories and remaining blockers are described above.

#### Original development attempt

This increment executes existing accepted producers. It does not replace them
with a fixture-only server, another evaluator or an inventory-only claim.
The selected candidate is accepted main
`eb6aa6a531cef67a0eac307404da981a5a600f07`, tree
`6da4d371bae069dee954f2d5f37415dee447a7b2`.

### Current decision

**NO-GO / NOT_READY; complete SOU-145 coverage is not delivered yet.**

The fresh [native Ubuntu run 40208279919](https://github.com/SoupTeam/soup-wall/actions/runs/40208279919)
actually ran Claude Code 2.1.251, the enforcing daemon and both pinned original
MCP servers with the owned scripted provider. The unchanged matched producer
executed 40 arms / 20 pairs: 38 passed arms, two failed arms, zero technical,
incomplete or cancelled arms. Benign work was **10/12**, refusal variants **8/8**,
with zero forbidden effects or forbidden result deliveries. Both failed arms
were protected `search-read-status` and `search-exclusion`, reported as
`supported_benign_interrupted`. These are useful-work interruptions, not a
security bypass or an environment failure. Root-cause ownership requires policy
triage; do not assume every interruption belongs to the detector owner.

All 40 arm rows report cleanup. The producer reports all owned processes stopped,
no forced cleanup, and unrelated state surviving until teardown. The separate
owned cleanup report also passed. This does not substitute for the unexecuted
cancel/restart/expiry scenarios.

The workflow stopped at the failed matched gate. Later Ask, prepared and
existing-project steps were skipped, so **15 Ask cases, 11 prepared cases and
three ordinary projects remain missing**. They are not counted as passing or
removed from the required inventory. WSL was not exercised. The original
installed 12-case producer is separate from the 20-pair matched mode and is not
claimed as a new complete pass either.

### Additional exact-source blockers

- At this accepted source, `qualify-pilot-ask.py::until` defaults to **20 seconds**
  and `Pilot.waiting()` calls it without an override. That producer's generic
  success cannot prove SOU-145's original **five-second first-pending bound**.
  SOU-141 owns timing optimization; SOU-145 must retain an independent five-second
  witness or an approved producer correction. No timeout was changed here.
- The selected matched report lacks the dossier's complete environment object;
  no kernel identity was invented from the reporter's Windows environment.
  The existing dossier therefore records environment binding as incomplete.
- The accepted existing-project producer has one legacy project. The additive
  three-project input option in this Draft has not been runtime-qualified and
  does not retroactively change the accepted-source attempt.
- The stopped hosted job does not provide a retained runnable installed bundle
  for completing its skipped steps. Hashes identify that bundle, not a promise
  that it can be reconstructed byte-identically. A later run needs its own fixed
  retained selection and must not merge its results into this attempt silently.

### Reproduce verification without executing a pilot

Download the original artifact ZIP (not an extracted/repacked archive):
artifact ID `12604653241`, name `sou111-native-preparation-40208279919`,
archive SHA-256 `796383e59bd1000203a40a866f82a4a78b86232e6fd9987c3373cbfc0c1a9141`.
It is 328,264 bytes with 249 members; the selected report member is
`sou111-qualification/report.json`. Keep the full archive private. Do not import
raw chat/log directories.

```sh
gh api repos/SoupTeam/soup-wall/actions/artifacts/12604653241/zip > /private/attempt-1.zip
python3 -B scripts/verify-sou145-evidence.py \
  --archive /private/attempt-1.zip --output /private/new-sou145-verification
```

The parent must exist and output must be new. The command materializes only
the pinned support/workload Git blobs, verifies the original archive digest,
then invokes the existing `pilot_dossier` contract and matched gate. It does not
extract the archive, execute a runtime or evaluate with a new scoring engine.
The dossier is bounded by its existing limits and written to a private directory
(POSIX 0700/0600; Windows uses the parent ACL). Missing Git objects fail rather
than lazy-fetch. Expected result: **exit 1 / NOT_READY**, with a retained JSON
ledger and scorecard. Corrupt inputs must not be normalized to success.

[Selection](evidence/sou145/attempt-1-selection.json) and
[sanitized original-result projection](evidence/sou145/attempt-1-summary.json)
bind source/tree, producers, binaries, policy, classifiers, profiles, archive
and member hashes. Historical SOU-106 results remain unchanged; this new 10/12
observation has its own source and run identity.

### Complete the missing execution, without relaxing the result

Use the existing [installed qualification procedure](INSTALLED_PILOT_QUALIFICATION.md)
to build and retain one explicit selected source/artifact set on an owned Linux
host. Run the existing matched, Ask/inbox, prepared and existing-project producers
against that same selection, retaining each nonzero exit and original output.
Do not dispatch another full matrix just to obtain green badges. A failure may
not erase later inventory items: execute unaffected producers only after their
prior owned cleanup is established; otherwise keep the remaining items incomplete.

The initial run used the existing workflow, unmodified, with
`native_preparation_only=true`, `matched_development_only=true`,
`stability_mode=off`, on a branch pointing to the exact accepted SHA above at
dispatch. Its head SHA is recorded by GitHub. The branch's later Draft commits
are not the runtime source of that attempt.

The new optional `--project-fixture` uses the original SOU-134 execution,
refusal, effect, isolation and cleanup checks. The legacy default and expectations
are retained. Its public synthetic data contains:

| Fixture | Additional ordinary work |
| --- | --- |
| `docs-code` | Multiple documentation/code/test files, useful guide read after refusals |
| `unicode-spaces` | Unicode and spaced root/relative paths, real original-server guide read |
| `local-history` | Two local Git commits, original `git_log` and useful documentation read |

All three require original useful results after refusal, in addition to the
unchanged five refusals and lifecycle cases. Source bytes are fixed in
`scripts/pilot_project_fixtures.py`; each report records their digest and nine
required cases. The input controls are not execution evidence.

After review of this producer addition, on its identified source and retained
selection, run each without dropping failures:

```sh
status=0
for project in docs-code unicode-spaces local-history; do
  python3 -B scripts/qualify-existing-pilot.py \
    --selection /private/fixed-selection.json --expected-commit FULL_REVIEWED_SHA \
    --strace /usr/bin/strace --project-fixture "$project" \
    --output "/private/new-project-$project" || status=1
done
exit "$status"
```

This command creates only harness-owned projects, not customer workspaces.
Do not combine these future identities with attempt 1 as if they were one run.
Link the reports to the existing dossier instead of introducing a second
evaluator. Complete three-project dossier ingestion remains follow-up work in
this Draft; none is claimed completed by the input option alone.

### Development checks and ownership

Local Windows checks: project-input controls **4/4**, existing dossier controls
**36/36**, and Python syntax parsing passed. TEMP/TMP used an owned writable
directory. These do not establish execution of the new three-project option.

SOU-145 owns missing qualification and evidence links. SOU-141 owns performance
changes, SOU-109 owns detector changes, TL owns shared CI/admission/main
integration. No production policy, broker TTL, resource limit, expected label,
paid model, private dataset, live-model efficacy or release claim is changed.
Keep this PR Draft until the missing execution and evidence links are completed.
