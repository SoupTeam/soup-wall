# SOU-91 CI scheduling evidence

This is a public, sanitized inventory. It contains GitHub run identities,
rounded timings and synthetic path sets only. It contains no runner logs,
credentials, private fixtures or claimed GitHub billing data.

## Frozen source and representative changes

The planning baseline is accepted main
`e3faa664f94ed788917131d35453f115598d6738`. The six path sets were
frozen before comparing outcomes in [frozen-scenarios.json](frozen-scenarios.json):
plain docs, Rust Agent/native, Gateway/Console, Python classifier/evaluation,
workflow changes and a Dependabot-style lockfile change. A path set is a
selection control, **not** a claim that one historical PR changed exactly
those files.

| Frozen case | Modeled job IDs after verified activation | Required security/runtime treatment |
| --- | ---: | --- |
| Plain docs | 1 | Documentation and five CodeQL language analyses |
| Rust Agent/native | 39 | Workspace, native Linux/macOS/Windows, original MCP, policy/license/supply chain |
| Gateway/Console | 29 | Workspace, SAML targets, real identity/storage, Docker, policy/license/supply chain |
| Python classifier/evaluation | 3 | Python/eval, benchmark, five CodeQL languages |
| Workflow/action/runner | 50 | Every registered PR job |
| Dependabot lockfile | 50 | Every registered PR job |

The four core `ci.yml` required checks in the live `main` ruleset remain
registered. GitHub treats a conditionally skipped job as successful for branch
rules. The production planner now **forces all 50 registered job IDs** until a
maintainer enables the repository switch and a live ruleset read confirms the
trusted aggregate status is required. The ruleset also
requires one review and CodeQL `high_or_higher` / `errors`; the patch script
refuses weakening them.

## Observed historical baseline

`scripts/ci_runner_metrics.py` read each latest workflow run and summed its
completed job start/end intervals. This is **observed job occupancy**, not the
organization's billed minutes. Wall time spans the observed workflow runs;
parallel jobs make it much smaller than the sum. The historical heads have
different base versions and path filters, so these are timing profiles, not a
causal before/after experiment.

| Comparable historical PR and principal `ci` run | Observed workflows | Job minutes | Wall minutes | Cancelled PR runs at head |
| --- | ---: | ---: | ---: | ---: |
| [Agent #175](https://github.com/SoupTeam/soup-wall/actions/runs/39062528621), head `8bc6395` | 27 | 172.92 | 15.00 | 0 |
| [Gateway #156](https://github.com/SoupTeam/soup-wall/actions/runs/39053478786), head `0461cfa` | 19 | 138.95 | 14.37 | 0 |
| [Classifier #162](https://github.com/SoupTeam/soup-wall/actions/runs/39050614680), head `104bb7c` | 26 | 167.40 | 14.92 | 0 |
| [Action bump #153](https://github.com/SoupTeam/soup-wall/actions/runs/39052657320), head `be31929` | 12 | 107.70 | 14.07 | 0 |
| [Older documentation/eval #91](https://github.com/SoupTeam/soup-wall/actions/runs/38361834066), head `5af88b9` | 3 | 26.07 | 4.42 | 0 |

The accepted main push `e3faa66` launched eight observed workflows. Its
immediate predecessor push `93bedc2` launched eight; `ci`, identity sandbox
and protected alert recovery were cancelled when newer main work superseded
them. This is observed cancellation, not recoverable billed-minute savings.
The historical Agent `ci` run had 11 exact Rust dependency cache hits and no
observed misses in the relevant jobs. A new shared-key generation can be cold
on its first PR run; that cost must be reported separately.

For orientation only, summing the five workflow timing profiles that would
have run on a current-main plain-docs PR (the always-on `ci`, gate validator,
license, monitoring and local test environment) gives **85.62 job minutes**
from the #175 run. That is a **counterfactual projection** using observed
durations, not a measured docs-only run. The older #91 run is not directly
comparable because its main and CodeQL configuration differed.

## Implemented-head measurement boundary

The implementation PR changes workflow and planner files, so its own trusted
plan deliberately requires all 50 registered job IDs plus the five CodeQL
analyses. At source `ee0f7392b605f9feb8ce70c530b9e2e755c6fdd2`, all
100 checks passed, with 247.82 observed job minutes, 16.65 wall minutes and
11 cold Rust-cache misses in the `ci` run. This is a full-run baseline, not
a selective after-run saving. The bootstrap fix is verified separately and
will have its own full-run CI result. The six frozen selective
scenarios are verified by executable planner/gate tests. Selected-job timing
estimates drawn from the historical profiles exclude newly introduced plan
jobs, unknown cache effects and jobs absent from those old heads; they are not
reported as actual savings. The 30% runner-minute reduction is a target to
verify on representative post-activation PRs, not a reason to omit a selected
security or runtime job. The organization's billed amount is unavailable to
this repository token.

The older Dependabot PR #152 head
`b2a556efded38da346fe05f5948e05ff418c00f3` returned **zero** managed
CodeQL runs for its exact SHA through the Actions API. A current reviewed
head (#175) showed all five analyses. The token received HTTP 403 when reading
the repository's default CodeQL configuration, so the maintainer procedure in
the [guide](../../CI_CHANGE_AWARE.md#missing-codeql-configuration-on-older-pr-heads)
requires authorized verification. No absent analysis is counted as a pass.
