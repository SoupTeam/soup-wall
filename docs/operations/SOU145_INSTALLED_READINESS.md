# SOU-145 installed pilot readiness: fresh development attempt

This increment executes existing accepted producers. It does not replace them
with a fixture-only server, another evaluator or an inventory-only claim.
The selected candidate is accepted main
`eb6aa6a531cef67a0eac307404da981a5a600f07`, tree
`6da4d371bae069dee954f2d5f37415dee447a7b2`.

## Current decision

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

## Additional exact-source blockers

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

## Reproduce verification without executing a pilot

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

## Complete the missing execution, without relaxing the result

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

## Development checks and ownership

Local Windows checks: project-input controls **4/4**, existing dossier controls
**36/36**, and Python syntax parsing passed. TEMP/TMP used an owned writable
directory. These do not establish execution of the new three-project option.

SOU-145 owns missing qualification and evidence links. SOU-141 owns performance
changes, SOU-109 owns detector changes, TL owns shared CI/admission/main
integration. No production policy, broker TTL, resource limit, expected label,
paid model, private dataset, live-model efficacy or release claim is changed.
Keep this PR Draft until the missing execution and evidence links are completed.
