# Change-aware CI and exact-source admission (SOU-91)

This guide describes the PR scheduler in `scripts/ci_impact.py`, its workflow
registration, and the trusted admission status. It does not change the release
workflow or authorize publication. The [frozen scenarios and observations](evidence/sou-91/README.md)
show the measurement boundary.

## Source and trust model

Every ready PR starts one `impact` job in `ci.yml`. Its reusable workflow
checks out the PR test-merge commit with two parents and refuses a checkout whose
parents differ from the event's base and head. The planner receives the actual
changed paths from that merge tree. **Until selective scheduling is activated,
every registered job runs even for a documentation-only PR.** Activation requires
the maintainer-controlled `SOU91_SELECTIVE_CI` repository variable and a live
readback of ruleset `24846282` proving that the aggregate context is required,
the original four required checks remain, review and CodeQL thresholds remain,
and enforcement is active. An absent variable, missing permission, API error or
unexpected ruleset forces full qualification. The trusted base admission process
repeats the ruleset read independently. Once activated, core jobs depend on `impact`, while component jobs consume the
same complete plan through the shared qualification workflow. Selected jobs run
the existing acceptance bodies; unselected jobs are explicitly skipped. Manual
`ci` dispatch selects full qualification; component dispatches and schedules run
the complete registered job set for that component.
Main pushes use the separate smoke path below. No private data, artifacts or
release credentials enter the planner.

## Cost policy: draft, ready and merged

- Develop in a **Draft PR**. A single Linux fast job checks Rust formatting,
  admission/scheduling regressions, documentation and rule-classifier units.
  The reusable impact job is skipped before allocating a runner, so none of
  the runtime components starts a planner or acceptance runner. Managed
  CodeQL remains enabled and independent; this is not a promise of zero cost.
  The four protected runtime/documentation jobs use different `Deferred - ...`
  names while draft. Their skipped results therefore cannot satisfy existing
  required contexts, including the transition before ready jobs are queued.
- **Ready for review** triggers the root CI and its selected components, plus
  trusted admission. Ready PR updates run qualification again. The existing full-plan
  bootstrap and protected checks are unchanged. Draft fast checks never
  substitute for runtime or security qualification.
- **Convert to draft** cancels outdated root CI and its components. Admission publishes
  a pending status and exits without a 45-minute polling runner. It never
  approves a draft. A conversion during evidence inspection also fails
  admission. Reopening and ready transitions are covered explicitly.
- **After merge**, one Linux smoke job builds the actual merged Agent/Gateway,
  checks the adapter contract and Agent CLI, and runs the isolated Gateway
  acceptance with an owned loopback upstream and SQLite. The duplicate
  Windows/macOS, all-features, Docker and integration matrix is not repeated
  on every main push. Managed CodeQL still runs on main. This short smoke is
  deliberately not a complete product acceptance or release authorization.
- Every registered workflow retains **Run workflow** for full qualification
  on a chosen ref. Run all applicable workflows for final release acceptance;
  neither draft nor post-merge smoke evidence can replace it. The release
  workflow and scheduled supply-chain scan are unchanged.
  The `ci` workflow also accepts `smoke_only: true` for testing just the smoke
  command on a branch before merging. The default is false (full qualification).

Cancellation is scoped by workflow and PR/ref; it does not cancel another PR.
PR Rust caches can now be saved by ready PR runs, under GitHub's PR merge-ref
cache scope. Privileged admission still checks out trusted base source only
and never downloads candidate caches or artifacts. Main smoke warms the base
Linux build cache. No branch protection or CodeQL threshold is changed here.

Observed baseline on October 18: PR #179 head
`02464de52f271d9a8ae2976c4d4231a849307c03` consumed 287.8 raw
runner-minutes across 102 job attempts, including a Git rerun. Main
`de54c0065d158203c6a840f4a60bc3eed6bddb29` consumed 128.2 raw
runner-minutes across 38 jobs. The admission job alone waited 18.4 minutes.
These are sums of job start/completion durations, not organization billing,
an average, or measured savings. Compare the new draft and main paths against
these baselines after installation. Ready runtime qualification stays intact.

The privileged admission workflow checks out **only trusted base source** on
`pull_request_target`, or the default-branch source on completion events. It parses PR files and GitHub API responses as data. It
never checks out or executes PR code, downloads PR artifacts, or restores a PR
cache. The base planner selects requirements independently of any plan reported
by the PR. A change to `.github/`, the planner, a runner/action, `Cargo.lock`,
the toolchain, a shared crate, an operational workflow document, a scenario
definition or an unknown path selects full qualification.

The admission status is attached to the current test-merge SHA, whose parents
must be the PR's current base and head. Every selected core/component must have a successful PR run at the exact head,
an `impact / Candidate <merge SHA>` job and every required OS/backend member in
the latest attempt. Components share the `ci.yml` run; legacy separate runs are
still verified when present.
Missing, failed, cancelled, timed-out, neutral, duplicate or unexpectedly
skipped required jobs fail admission. A pending run stays blocking until completion events provide the missing
evidence; no runner waits idle for it. Moving the head or base invalidates the
result and requires current-source qualification.

GitHub's managed CodeQL default setup currently records analyses on the **PR
head SHA**, while PR runtime workflows check out the test-merge SHA. Admission
requires successful `actions`, `c-cpp`, `javascript-typescript`, `python` and
`rust` CodeQL jobs on that exact head. This distinction is retained in the
status evaluation; a neutral umbrella check or an absent analysis cannot
substitute for a language result. The repository's existing CodeQL severity
thresholds remain in the active ruleset. This check does not claim that a
head-only CodeQL database analyzed the merged tree.

## Selection contract

`WORKFLOW_JOBS` in `scripts/ci_impact.py` registers core jobs and the original
manually dispatchable component sources. Shared component qualification, VPS,
release and scheduling/gate workflows are separate orchestration surfaces. `CHECK_NAMES` in
`scripts/ci_admission.py` names matrix and custom job checks. Tests refuse a
new unregistered workflow or job. Add a new component by registering its job
IDs, expected check names and impact group. Keep the original manual job dependent
on its reusable `impact` job, then regenerate `ci-components.yml` with
`python3 scripts/ci_components.py`. Changes to this contract run the full set because they
are under `.github/` or `scripts/ci_`.

| Changed path | Required work |
| --- | --- |
| Plain project documentation, after verified activation | Documentation links and the five CodeQL analyses; component jobs skip without separate planners or runtime runners |
| Agent/native source and profiles | Workspace Rust/Python checks, native Linux/macOS/Windows and original-server MCP controls, policy, license, supply chain and monitoring |
| Gateway/Console source and deployment | Workspace, SAML targets, Redis/PostgreSQL, Docker, identity, managed Agent and TLS controls, policy, license and supply chain |
| Evaluation and classifier Python | Python classifier/evaluation, benchmark and CodeQL; no Rust build unless another changed path requires it |
| Workflow/action/runner, shared dependency, scenario, operational contract, unknown path | Every registered PR job and all five CodeQL analyses |

Python classifier and evaluation steps moved unchanged from the Rust workspace
job to their own Linux job. The existing Gateway, Agent and platform acceptance
bodies remain in the manual sources and their checked generated shared workflow. `gate-ci.yml` remains part of full workflow changes,
while its redundant `feature/*` push and two one-off branch push triggers were
removed. Main pushes run only the established merged-source smoke alongside CodeQL. The release
workflow and its publication conditions were not changed.

`ci.yml` Rust caches share dependency entries only between compatible hosted
jobs. Cache identity includes the lock/toolchain hashes, built-in Rust
environment/toolchain fingerprint, runner OS/architecture and the default,
all-features or SAML target profile. Ready PRs may save entries in their isolated PR merge-ref cache scope; they
cannot seed a cache later restored by privileged admission. Main smoke may save
the compatible main Linux build cache.
The admission workflow uses no cache. A cold new key is a performance cost, not
evidence of a passing test; record cache hits/misses from Actions logs.

## Local and hosted verification

```bash
python3 -m unittest discover -s scripts/tests -p 'test_ci_*.py' -v
python3 scripts/ci_impact.py --paths-json /path/to/one-scenario.json
python3 scripts/check_docs.py
```

Run `actionlint` against all workflow files before submitting changes. The
frozen six scenarios are in `evidence/sou-91/frozen-scenarios.json`. Use
`scripts/ci_runner_metrics.py --pr NUMBER` with a read-only `GITHUB_TOKEN` to
measure a comparable PR: it sums each completed job's observed start/end time
and reports wall time, cancellations and missing timings separately. It does
**not** report the organization's billed minutes. Never describe selected-job
timings from an older PR as a measured after-run saving.

For explicit full qualification, dispatch `ci` with `smoke_only: false` on a
reviewed source ref; it includes all components and ignores path selection.
Original component workflows remain available for focused manual qualification.
Record each run ID and verify all expected jobs. The release workflow is a
separate operator-controlled gate and must not be dispatched as an intermediate
CI measurement. The aggregate PR status accepts only `pull_request` runs and
managed CodeQL `dynamic` runs for its exact source, never a manual dispatch.

## Safe bootstrap and maintainer activation

The current `main` ruleset is ID `24846282` (verify the live ID first). It has
strict required `Documentation links`, `test`, `all-features` and
`agent-windows-security` checks from GitHub Actions integration `15368`, one
approving review, and CodeQL `high_or_higher` security alerts / `errors` code
quality threshold. A token without ruleset administration cannot change this
configuration. The PR's trusted `pull_request_target` workflow also cannot
run from a file that is only on a PR branch; it becomes available when merged
to the default branch. **Merge this code only with the activation variable
absent.** The default full plan is a bootstrap invariant, tested for a plain
`README.md` change. The existing required execution checks continue to run.

After review and installation on main, keep the variable absent and verify a
controlled documentation-only PR still runs all registered jobs. Confirm its
`SOU-91 candidate admission` status targets the current test-merge commit.
Run positive, missing, failed and stale-candidate controls against the trusted
gate; a skipped required job must fail. Do not use a neutral CodeQL analysis as
a successful control. Then prepare an **additive, reviewable** ruleset payload:

```bash
gh api repos/SoupTeam/soup-wall/rulesets/24846282 > current-ruleset.json
python3 scripts/sou91_ruleset_patch.py current-ruleset.json proposed-ruleset.json
diff -u current-ruleset.json proposed-ruleset.json
```

The preparation script refuses missing old checks, non-strict enforcement,
changed CodeQL thresholds, missing review or an unexpected integration ID. An
administrator must review the output, apply it with
`gh api --method PUT repos/SoupTeam/soup-wall/rulesets/24846282 --input proposed-ruleset.json`,
read the ruleset back, and verify that all prior checks and CodeQL thresholds
remain while the new context is required. Do not remove old requirements to
make the new status green. Only after the gate controls and required-context
readback succeed may an authorized maintainer activate selection:

```bash
gh variable set SOU91_SELECTIVE_CI --body enabled-after-negative-controls --repo SoupTeam/soup-wall
gh variable get SOU91_SELECTIVE_CI --repo SoupTeam/soup-wall
```

The planner reads the ruleset again on each PR run; the trusted gate does so
independently. If either cannot verify the ruleset, the planner runs full, or
the gate demands full evidence and blocks an insufficient run. Remove the
variable to return to full qualification immediately. After activation, run
controlled selective PRs for the six frozen path sets and record exact source,
selected and skipped jobs, CodeQL, cache hits/misses, observed job minutes,
wall time and cancellations against comparable full runs. Keep SOU-91 open
until those measurements and negative controls are reviewed. The current
workflow-changing PR is a full run and cannot establish the 30% target.

## Missing CodeQL configuration on older PR heads

An older PR head can show no CodeQL jobs even though current PRs have all five.
For example, the read-only API returned zero managed CodeQL runs on old PR
`#152` head `b2a556efded38da346fe05f5948e05ff418c00f3`; current PR `#175`
showed five successful analyses on its reviewed head. An administrator should
first refresh the old PR against current main, without changing the CodeQL
ruleset, then inspect the new head's CodeQL runs and the PR checks panel. If
configuration is still missing, inspect **Settings → Security and quality →
Advanced Security → CodeQL default setup** and the five language/threshold
settings. The current token received HTTP 403 for the default-setup API; only
an authorized maintainer can verify that setting. Do not add a duplicate
advanced-setup workflow, lower thresholds, or treat missing/neutral analyses
as a pass. The trusted aggregate status stays red or pending until evidence is
complete.

## Single-planner migration

Trusted admission also accepts registered component checks inside the exact-source
`ci.yml` run, under `Components / <original-workflow> / <original-job-name>`.
Every selected matrix member and the merge-SHA planner remain mandatory. A green
CI run without those exact checks is refused. An existing failed legacy component
run cannot be hidden by the central run. This permits replacing duplicate planners
after this verifier compatibility is installed; it does not activate selective CI,
change required checks, or remove any runtime/security acceptance.

### Central component execution

Ready PRs now start `ci.yml` once. Its single source-bound planner supplies the
complete selection to `ci-components.yml`; the latter runs the original component
jobs without another planner. The original 34 workflows retain manual dispatch
(and the supply-chain schedule), but do not independently start on PR updates.
`python3 scripts/ci_components.py` regenerates the shared workflow from those
manual sources; `--check` and the CI contract suite reject drift. Edit the original
job, regenerate, and retain its runtime/artifact/matrix controls. The four existing
required core check names, separate CodeQL and privileged base-branch admission
are unchanged. Drafts and main smoke never invoke component qualification.

This removes 34 repeated planner allocations per full Ready run: the expected
full check count falls from 105 to 71 with the same runtime matrix. This is a job
count reduction, not a measured percentage of billed cost. Selective scheduling
still requires its reviewed activation and live required-context readback.

### Completion-driven admission

The privileged admission workflow checks once on PR updates and again when the
central CI or managed CodeQL run completes. Missing evidence remains a pending
blocking status; it never becomes green from a timeout or skipped test. This
avoids allocating an idle runner for up to 45 minutes. Routing reads the run and
current PR from the repository API, ignores obsolete heads and validates the
upstream workflow path/event; it never downloads artifacts or executes PR code.
CodeQL's dynamic `PR #*` workflow names are matched by a workflow-name glob.
Only trusted base/default-branch scripts are executed. An older PR that still
uses legacy parallel workflows must refresh from current main before it can
rely on the new completion orchestration. Full legacy manual qualification is
still available and the trusted verifier retains its legacy evidence support.
