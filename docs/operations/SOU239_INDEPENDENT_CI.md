# SOU-239: independent CI component execution

The accepted SOU-192 preflight still exists as three **required checks**:
Linux `test`, `Native macOS admission resilience`, and Windows
`agent-windows-security`. SOU-239 removes their broad scheduling edges from
unrelated jobs. A successful component is evidence only for itself. The
trusted SOU-91 verifier continues to require every selected central and
component job, every matrix member, all five CodeQL analyses, the exact
base/head/merge candidate and the current run attempt. A missing, failed,
cancelled or skipped selected check cannot be replaced by another job's pass.

## Reproduced old graph and bounded observation

Accepted main `8003fac2d271156e2229c8c15c6eddb98ee2da8e` had seven
deferred parent jobs (`components`, macOS lifecycle, all-features, SAML target
matrix, Redis, PostgreSQL and Docker). Each needed `impact` **and all three**
preflight jobs. That is 21 broad preflight edges. The component call enclosed
47 registered source jobs; six had an additional real edge to the immutable
`ci-builds--agent-default-ubuntu2404` producer.

[PR #359 ci run 41855378981](https://github.com/SoupTeam/soup-wall/actions/runs/41855378981)
at head `67422d7c4c2a245226a2a4e6e2bf2c4533e42172` shows the concrete gap.
On attempts 1, 2 and 3, `Native macOS admission resilience` ended
`cancelled` with `runner_id=0` and zero steps. In attempt 3, the parent
`Components` and the six other deferred parent jobs were skipped. The 47
component jobs therefore produced no execution evidence; those skips are not
test failures or passes. The existing required checks correctly blocked merge.

After this change, those seven parent jobs each need only the successful
exact-source `impact` plan. The 47 generated component jobs keep their
registered source commands, runner selectors, matrices, evidence uploads and
conditions. Only the six reviewed build consumers need the producer. Every
generated component condition now explicitly checks `!cancelled()`; a
cancelled or superseded run does not start new children, and an active run's
failed producer still reaches the existing fail-closed consumer guard.
Independent Linux/Windows and SAML matrix members may finish while a macOS
allocation fails; final admission still refuses that candidate.

## Review the source, platform and artifact map

Run `python3 scripts/ci_components.py --inventory` to emit the finite JSON
map derived from `WORKFLOW_JOBS`, the original manual workflow `runs-on`
selector and `BUILD_CONSUMERS`. Its 47 entries name the source workflow/job,
generated job, runner expression and optional producer edge. Matrix and
operator-variable runner expressions remain expressions until GitHub resolves
them; the inventory does not guess an allocated host. The original source
workflows are the executable specification. `python3 scripts/ci_components.py
--check` confirms the generated mirror matches them.

| Central job | Runner/inputs | Artifact dependency |
| --- | --- | --- |
| `components` | Called workflow with registered Linux, Windows, macOS and matrix jobs | Six consumers depend on `ci-builds`; other jobs have no build edge |
| `agent-lifecycle-macos` | macos-15; own source checkout/build | None |
| `all-features` | ubuntu-24.04; own source checkout/build | None |
| `saml-release-targets` | Ubuntu, macOS ARM64, macOS Intel and Windows matrix; own target builds | None |
| `redis-integration` | ubuntu-latest and disposable Redis service | None |
| `postgres-integration` | ubuntu-latest and disposable PostgreSQL service | None |
| `docker-build` | ubuntu-latest, source Docker context | None |

The exact plan still comes from the protected merge candidate. Unknown paths,
CI and registry changes, incomplete selection and mixed changes retain the
conservative full plan. Draft PRs run fast checks only; this graph change does
not make Draft evidence acceptable to admission. `workflow_dispatch`
`smoke_only` remains isolated from full qualification.

## Focused verification and handoff

Run `python3 -m unittest scripts.tests.test_ci_preflight
scripts.tests.test_ci_components scripts.tests.test_ci_impact
scripts.tests.test_ci_central_admission -v`, then `python3
scripts/ci_components.py --check`. These controls read the checked-in
conditions, enumerate every source/runner/producer mapping, model allocation
before the first step and ordinary failures, and exercise the trusted job
verifier's selected failures, missing evidence, stale heads and exact-source
transitions. They are offline contracts, not hosted runtime evidence.

The team lead owns the final Ready run on the reviewed source. Record the
actual completed versus unexecuted jobs, run/attempt, head and merge parents,
and five CodeQL languages. Do not claim the before-run skips as after-run
executions or publish a success status from this guide. No runner-minute or
billing saving is measured here; concurrent work can raise consumed runner
time on a failed candidate while producing useful independent evidence.
