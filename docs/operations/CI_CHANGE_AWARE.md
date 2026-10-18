# Change-aware CI and exact-source admission (SOU-91)

This guide describes the PR scheduler in `scripts/ci_impact.py`, its workflow
registration, and the trusted admission status. It does not change the release
workflow or authorize publication. The [frozen scenarios and observations](evidence/sou-91/README.md)
show the measurement boundary.

## Source and trust model

Every registered PR workflow starts a small `impact` job. Its reusable workflow
checks out the PR test-merge commit with two parents and refuses a checkout whose
parents differ from the event's base and head. The planner receives the actual
changed paths from that merge tree. **Until selective scheduling is activated,
every registered job runs even for a documentation-only PR.** Activation requires
the maintainer-controlled `SOU91_SELECTIVE_CI` repository variable and a live
readback of ruleset `24846282` proving that the aggregate context is required,
the original four required checks remain, review and CodeQL thresholds remain,
and enforcement is active. An absent variable, missing permission, API error or
unexpected ruleset forces full qualification. The trusted base admission process
repeats the ruleset read independently. Once activated, a selected job depends
on `impact` and runs the existing acceptance body; an unselected job is
explicitly skipped. A manual
`workflow_dispatch`, scheduled run or main push selects the complete registered
job set. No private data, artifacts or release credentials enter the planner.

The privileged `pull_request_target` admission workflow checks out **only the
trusted base commit**. It parses PR files and GitHub API responses as data. It
never checks out or executes PR code, downloads PR artifacts, or restores a PR
cache. The base planner selects requirements independently of any plan reported
by the PR. A change to `.github/`, the planner, a runner/action, `Cargo.lock`,
the toolchain, a shared crate, an operational workflow document, a scenario
definition or an unknown path selects full qualification.

The admission status is attached to the current test-merge SHA, whose parents
must be the PR's current base and head. Each selected workflow must have a
successful PR run at the exact head and an `impact / Candidate <merge SHA>` job,
plus every required OS/backend job successful in the latest run attempt.
Missing, failed, cancelled, timed-out, neutral, duplicate or unexpectedly
skipped required jobs fail admission. A pending run stays pending only within
the 45-minute wait; expiration is a failure. Moving the head or base invalidates
the result and requires a new run.

GitHub's managed CodeQL default setup currently records analyses on the **PR
head SHA**, while PR runtime workflows check out the test-merge SHA. Admission
requires successful `actions`, `c-cpp`, `javascript-typescript`, `python` and
`rust` CodeQL jobs on that exact head. This distinction is retained in the
status evaluation; a neutral umbrella check or an absent analysis cannot
substitute for a language result. The repository's existing CodeQL severity
thresholds remain in the active ruleset. This check does not claim that a
head-only CodeQL database analyzed the merged tree.

## Selection contract

`WORKFLOW_JOBS` in `scripts/ci_impact.py` registers every PR workflow except
the release workflow and the two scheduling/gate workflows. `CHECK_NAMES` in
`scripts/ci_admission.py` names matrix and custom job checks. Tests refuse a
new unregistered workflow or job. Add a new component by registering its job
IDs, expected check names and impact group, then make its jobs depend on the
reusable `impact` job. Changes to this contract run the full set because they
are under `.github/` or `scripts/ci_`.

| Changed path | Required work |
| --- | --- |
| Plain project documentation, after verified activation | Documentation links and the five CodeQL analyses; other workflows report a successful plan and skip their runtime jobs |
| Agent/native source and profiles | Workspace Rust/Python checks, native Linux/macOS/Windows and original-server MCP controls, policy, license, supply chain and monitoring |
| Gateway/Console source and deployment | Workspace, SAML targets, Redis/PostgreSQL, Docker, identity, managed Agent and TLS controls, policy, license and supply chain |
| Evaluation and classifier Python | Python classifier/evaluation, benchmark and CodeQL; no Rust build unless another changed path requires it |
| Workflow/action/runner, shared dependency, scenario, operational contract, unknown path | Every registered PR job and all five CodeQL analyses |

Python classifier and evaluation steps moved unchanged from the Rust workspace
job to their own Linux job. The existing Gateway, Agent and platform acceptance
bodies remain in place. `gate-ci.yml` remains part of full workflow changes,
while its redundant `feature/*` push and two one-off branch push triggers were
removed. Main pushes still run their established qualification. The release
workflow and its publication conditions were not changed.

`ci.yml` Rust caches share dependency entries only between compatible hosted
jobs. Cache identity includes the lock/toolchain hashes, built-in Rust
environment/toolchain fingerprint, runner OS/architecture and the default,
all-features or SAML target profile. Only trusted main pushes save these
entries; PRs may restore but cannot seed a cache later used by trusted work.
The admission workflow uses no cache. A cold new key is a performance cost, not
evidence of a passing test; record cache hits/misses from Actions logs.

## Local and hosted verification

```bash
python3 -m unittest discover -s scripts/tests -p test_ci_impact.py -v
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

For explicit full qualification, run the registered workflows with
`workflow_dispatch` on a reviewed source ref; dispatches ignore path selection.
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
