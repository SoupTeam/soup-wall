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
| Rust Agent/native | 41 | Workspace, native Linux/macOS/Windows, original MCP, policy/license/supply chain |
| Gateway/Console | 30 | Workspace, SAML targets, real identity/storage, Docker, policy/license/supply chain |
| Python classifier/evaluation | 3 | Python/eval, benchmark, five CodeQL languages |
| Workflow/action/runner | 53 | Every registered PR job |
| Dependabot lockfile | 53 | Every registered PR job |

The four core `ci.yml` required checks in the live `main` ruleset remain
registered. GitHub treats a conditionally skipped job as successful for branch
rules. The production planner **forces all registered job IDs** until a
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
a selective after-run saving. The later trusted-workflow revision fix (#189)
and CodeQL completion subscription fix (#203) were reviewed and merged before
the October 20 activation control. The six frozen selective scenarios are
verified by executable planner/gate tests. Selected-job timing
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

## October 19 bootstrap and October 20 activation

At live main `30ced9431990e8aa55381194d7616daa87733344`, ruleset
[`24846282`](https://github.com/SoupTeam/soup-wall/rules/24846282) was active
and strict. Its four required contexts remained `Documentation links`, `test`,
`all-features` and `agent-windows-security`; the aggregate
`SOU-91 candidate admission` was absent. The review count remained one and
CodeQL thresholds remained `high_or_higher` security / `errors` quality.
The repository variable listing contained no `SOU91_SELECTIVE_CI`.
The observing account had `push` but no `maintain` or `admin` permission.
This was a **safe full-qualification bootstrap**, before selective activation.
Running the checked-in patch generator against that live ruleset produced
exactly one additional required-status entry:
`{"context":"SOU-91 candidate admission","integration_id":15368}`.
The existing four entries, review rule and CodeQL rule were unchanged. The
payload was prepared in memory; no repository setting was changed.

An API-backed read-only probe of open [PR #189](https://github.com/SoupTeam/soup-wall/pull/189)
at head `cb746dd097ca6119a234590091d059651bf205e9` returned
`pending: selected workflow missing: agent-doctor.yml` while full qualification
was unfinished. Supplying a deliberately stale event base to the same verifier
returned `failure: PR source moved during admission`. The stale result is a
local input control, not a hosted status or a complete positive/negative
activation test. PR #189 repaired trusted-workflow/script revision alignment
before the final gate controls.

The upgraded read-only timing command
`python3 scripts/ci_runner_metrics.py --pr 190 --run-id 39229893593`
observed a **full** PR #190 qualification at head
`d07ce330919f1aa49bab70d4f9519a396c286633`: central CI took 309.43
raw runner-minutes over 63 actual job executions in two attempts; 61 copied
forward job records were deduplicated. Managed CodeQL run `39229888296` took
17.62 raw runner-minutes, making the complete observed total 327.05. The
combined elapsed wall time from run creation to the last update was 38.98
minutes, including the interval before the CI rerun.
This run changed Windows Agent code and operational documentation, so it
cannot establish frozen-set selective savings or the 30% goal. Cache misses
were not measured by the jobs API and remain unknown.

On October 20, an authorized maintainer installed and read back the additive
context in live ruleset `24846282`. It is active and strict, now requiring the
original four contexts **and** `SOU-91 candidate admission`, all from GitHub
Actions integration `15368`. One approving review and CodeQL security
`high_or_higher` / quality `errors` remain. The live repository variable is
`SOU91_SELECTIVE_CI=enabled-after-negative-controls`. The maintainer's
[control report](https://github.com/SoupTeam/soup-wall/pull/201#issuecomment-6288586427)
records pending admission for missing evidence, failure for a failed selected
CI job, and rejection of success from an older candidate. PR #203 repaired the
CodeQL completion subscription without weakening the gate and was merged as
`fb90415772c223d0234af484e278bda2c01b95f6` before the final control.

The final [documentation-only control #201](https://github.com/SoupTeam/soup-wall/pull/201)
changed only `README.md` at head
`c0b18f49ef3ee60f35889f13d994699b9812f1ee`. Its exact candidate was
`bb21623517b4392ea3acf27c8a8799162ac8916a`. Central
[CI run 39404708355](https://github.com/SoupTeam/soup-wall/actions/runs/39404708355)
executed the planner and Documentation links (0.23 raw runner-minutes, 0.30
wall minutes); 54 unselected jobs skipped. Managed
[CodeQL run 39404707367](https://github.com/SoupTeam/soup-wall/actions/runs/39404707367)
completed all five languages (12.30 raw runner-minutes). The combined observed
occupancy was **12.53 runner-minutes** over **9.15 elapsed wall minutes**; no
same-head PR runs were cancelled. Admission automatically changed from pending
to success at 2026-10-20 10:09:15 UTC after CodeQL completed, without manual
status writing or an admission rerun. The Actions jobs API does not report
cache hits/misses, so that field remains unavailable. This control PR was
closed without merge. The [machine-readable observation](observed-docs-only.json)
lists its executed and skipped checks and timing boundaries.

## Post-activation representative observations

The table reports completed, exact-head `pull_request` CI and managed CodeQL
observations. "Runner minutes" sums actual job intervals, including all five
CodeQL language analyses; "wall" spans the first run creation to the last run
update. A skip consumes no runner in this inventory. Job selection is checked
against the current trusted path model, while admission's success is checked on
the corresponding test-merge candidate. The linked JSON files retain the full
active/skipped check lists and unavailable fields. The four #205 controls each
appended only a comment to one frozen path. They isolate scheduling and gate
behavior; they do not benchmark the cost of a substantive code or dependency
change. #201 and #199 are previously completed owner PRs reused as controls.

| Frozen class / actual control | Central CI | CodeQL | Executed / skipped CI jobs | Runner min (CI + CodeQL) | Wall min | Central cache misses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [Docs #201](observed-docs-only.json), exact `README.md` | [39404708355](https://github.com/SoupTeam/soup-wall/actions/runs/39404708355) | [39404707367](https://github.com/SoupTeam/soup-wall/actions/runs/39404707367) | 2 / 54 | 0.23 + 12.30 = **12.53** | 9.15 | 0 configured cache jobs |
| [Rust Agent #205](observed-rust-agent.json), exact `crates/agentfw/src/native.rs` | [39416298038](https://github.com/SoupTeam/soup-wall/actions/runs/39416298038) | [39416285451](https://github.com/SoupTeam/soup-wall/actions/runs/39416285451) | 46 / 14 | 257.18 + 18.20 = **275.38** | 21.12 | 29 observed misses |
| [Gateway #205](observed-gateway-console.json), exact `crates/proxy/src/main.rs` | [39419161118](https://github.com/SoupTeam/soup-wall/actions/runs/39419161118) | [39419149169](https://github.com/SoupTeam/soup-wall/actions/runs/39419149169) | 39 / 25 | 143.70 + 15.77 = **159.47** | 14.08 | 21 observed misses |
| [Python #205](observed-python-eval.json), exact `eval/eval_runner.py` | [39414604866](https://github.com/SoupTeam/soup-wall/actions/runs/39414604866) | [39414598216](https://github.com/SoupTeam/soup-wall/actions/runs/39414598216) | 4 / 52 | 1.67 + 15.23 = **16.90** | 12.45 | 1 observed miss |
| [Workflow #199](observed-workflow-change.json), broader workflow-containing PR | [39408087772](https://github.com/SoupTeam/soup-wall/actions/runs/39408087772) | [39408085696](https://github.com/SoupTeam/soup-wall/actions/runs/39408085696) | 64 / 2 | 315.82 + 13.88 = **329.70** | 24.70 | 44 observed misses |
| [Lockfile #205](observed-lockfile.json), exact `Cargo.lock` comment | [39425032055](https://github.com/SoupTeam/soup-wall/actions/runs/39425032055) | [39424981929](https://github.com/SoupTeam/soup-wall/actions/runs/39424981929) | 64 / 2 | 320.77 + 15.17 = **335.94** | 27.92 | 44 observed misses |

The workflow example changed nine files, including two `.github/workflows/`
paths, so it exercises the frozen workflow class's **full-plan branch** but is
not an exact one-file change. All modeled required checks and five CodeQL
analyses succeeded in all six observations. The Python candidate
`f0e1d5cf5289f01c5e1d1dd7348940837657caec` gained automatic admission
success at 2026-10-20 11:36:19 UTC after CodeQL; its same-head CI had no
cancellations. The Rust candidate
`40a20550b4f25c0a5f06adf729c1b2d46b995618` gained automatic admission
success at 11:58:58 UTC after all 46 selected CI executions and five CodeQL
analyses succeeded. Its one cancelled same-head CI run was the Draft fast job
superseded by Ready qualification; it is not counted as a saving. The older
Python probe head was superseded when main advanced and its CI was cancelled;
that head is excluded from the exact-head observation. Cache misses above
count literal `No cache found.` messages in the selected CI job logs; managed
CodeQL cache behavior is not exposed here.

The Gateway candidate `48f21dd57934b4bed0b576dae24c1d82ab50c84c`
gained automatic admission success at 12:15:48 UTC after all 39 selected CI
executions and five CodeQL analyses succeeded. A Draft fast run was cancelled
at the same head when Ready qualification started; it is not a saving.
The lockfile head `620ff9775104999c64001d12fb89e343aa23fe49` changed only
`Cargo.lock`; it simulates a dependency-file path without claiming the actor
was Dependabot. The full plan ran, with all 53 modeled registered job IDs and
five CodeQL analyses successful. Admission became success on exact candidate
`c4e9eb78e86e02512ea24d0529ac0e5952994c9f` at 13:15:23 UTC. Its one
cancelled same-head run was the Draft fast workflow superseded by Ready
qualification, not saved CI. The lockfile class deliberately saves **zero**
runner-minutes by selection.
Historical full-run profiles above and these after-runs have different
source/base and workflow versions; their numeric difference is **not** a
measured causal saving. Keep SOU-91 open until the measurements and their
limits are reviewed.

## Source-matched full-mode comparison

An explicit `ci.yml` [full dispatch 39419266459](https://github.com/SoupTeam/soup-wall/actions/runs/39419266459)
ran on the **same Gateway head** `510df0d37fc7a6316bbd2c58742a97f3aa5afbed`
as the selective PR run above. The [full-run observation](observed-gateway-full.json)
shows all 53 modeled registered job IDs present and successful in the latest
attempt. Its first attempt consumed 301.72 raw CI runner-minutes but failed at
the SAML/PostgreSQL `callback-analyst` timeout. One `--failed` retry on the
unchanged SHA passed; the two attempts together consumed **330.42 CI
runner-minutes**, 66 actual executions, 62 copied-forward records counted only
once, 42.27 wall minutes and 46 observed Rust-cache misses. The failed first
attempt and retry are both included, not discarded.

The source-matched selective Gateway CI consumed 143.70 runner-minutes and 21
cache misses. The actual central-CI difference is **186.72 raw runner-minutes
(56.5%)**. Adding the *same* 15.77-minute PR CodeQL result to each side gives
346.19 full-mode-equivalent versus 159.47 selective runner-minutes, a 53.9%
reduction in this control. CodeQL still ran once and was never skipped. Manual
dispatch checks the branch head while PR CI checks its test-merge commit; the
source change was only a comment and both were rooted in the same base, but
the event, cache scope and one failed/retried job differ. These figures are a
source-matched observed control, not organization billing or a universal
expected saving.

An explicit [Python full dispatch 39421528412](https://github.com/SoupTeam/soup-wall/actions/runs/39421528412)
ran on the exact selective Python source head
`2d4c2345fe7b281f681283ca50589c171607bf8f`. Its
[observation](observed-python-full.json) records one successful attempt,
all 53 modeled registered job IDs, 64 executed CI jobs, **323.98 CI
runner-minutes**, 27.05 wall minutes and 44 cold cache misses across 44
configured cache jobs. The selective PR CI used 1.67 runner-minutes and one
cache miss. The central-CI difference is **322.31 raw runner-minutes (99.5%)**.
Adding the same 15.23-minute managed PR CodeQL run to both sides gives 339.21
full-mode-equivalent versus 16.90 selective runner-minutes, a 95.0% reduction
for this control. The dispatch is not an admission-eligible PR run; branch-head
versus test-merge execution and event-specific caches limit causal inference.

An explicit [docs full dispatch 39425604998](https://github.com/SoupTeam/soup-wall/actions/runs/39425604998)
ran on the exact docs-only source head
`c0b18f49ef3ee60f35889f13d994699b9812f1ee`. Its
[observation](observed-docs-full.json) records one successful attempt, all 53
modeled registered job IDs, 64 executed CI jobs, **321.42 CI runner-minutes**,
24.98 wall minutes and 44 cold cache misses. The selective docs CI used 0.23
runner-minutes and had no configured cache job. The central-CI difference is
**321.19 raw runner-minutes (99.9%)**. Adding the same 12.30-minute managed PR
CodeQL run to both sides gives 333.72 full-mode-equivalent versus 12.53
selective runner-minutes, a **96.2%** reduction for this control. The manual
dispatch is not admission-eligible, and its branch-head execution and cache
scope differ from the PR's test-merge execution.

The [Rust full dispatch 39425582108](https://github.com/SoupTeam/soup-wall/actions/runs/39425582108)
used the same source head `5e8eb04c3ea5a7ef51fbe10b1a02b07210c9cddb`
as the selective Rust PR. Its first attempt ran all registered jobs and took
313.30 CI runner-minutes, but `Native macOS admission resilience` failed when
GitHub Artifact upload returned `ENOTFOUND` after its local tests passed.
Its first-attempt CI logs showed 44 cold cache misses in 44 configured cache
jobs and no observed restores; the retried macOS cache state is not included
in that count.
One `--failed` rerun on that unchanged SHA succeeded. The
[two-attempt observation](observed-rust-full.json) counts **330.10 CI
runner-minutes**, 65 actual executions, 63 copied-forward records counted
once, 45.45 wall minutes, all 53 modeled registered job IDs successful in the
latest attempt, and no unavailable timings. The selective Rust CI used 257.18
runner-minutes; the completed central-CI difference is **72.92 raw
runner-minutes (22.1%)**. Adding the same 18.20-minute PR CodeQL run to both
sides gives 348.30 full-mode-equivalent versus 275.38 selective, a **20.9%**
reduction. Omitting the failed retry for sensitivity would give 331.50 versus
275.38 including CodeQL, or 16.9%; the failed first attempt alone is not a
successful full qualification. The artifact upload failure and different PR /
manual event cache scopes limit what the comparison can predict.

| Frozen class | Full-mode-equivalent runner min | Selective runner min | Difference | Reduction |
| --- | ---: | ---: | ---: | ---: |
| Docs | 333.72 | 12.53 | 321.19 | 96.2% |
| Rust Agent/native | 348.30 | 275.38 | 72.92 | 20.9% |
| Gateway/Console | 346.19 | 159.47 | 186.72 | 53.9% |
| Python classifier/eval | 339.21 | 16.90 | 322.31 | 95.0% |
| Workflow change, full by design | 329.70 | 329.70 | 0.00 | 0.0% |
| Lockfile, full by design | 335.94 | 335.94 | 0.00 | 0.0% |
| **Six-case total** | **2033.06** | **1129.92** | **903.14** | **44.4%** |

For the four selective rows, full-mode-equivalent means the exact-source
manual full CI plus the *same observed PR CodeQL run* on both sides; CodeQL
did not disappear or run a second time. The two full-by-design rows reuse
their actual PR qualification on both sides. This is an equal-weight frozen
six-case sample, not a traffic-weighted forecast or GitHub billing. Failed
first attempts and successful reruns in the Rust and Gateway full controls
raise the full total. If only their first-attempt CI occupancy is used as a
sensitivity bound, the full-mode sum is 1987.56 and the gap is 857.64
runner-minutes (43.2%); those first attempts failed, so that bound is **not**
a successful full-run baseline. The actual completed-control total above
includes both attempts. No result from #205 altered another PR's source,
review state or required checks.
