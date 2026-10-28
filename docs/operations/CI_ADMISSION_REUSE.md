# Bounded duplicate CI admission (SOU-160)

The required `SOU-91 candidate admission` context remains a trusted,
merge-commit status. Its verifier runs from the default branch and never
checks out or imports PR code or artifacts. SOU-160 changes only the work done
by a **later** verifier for a candidate that already has a successful, trusted
verification. The repository variable `SOU160_ADMISSION_REUSE` is absent by
default. Any value other than `enabled-after-controls` retains the existing
full verifier and its status writes.

## Observed duplicate and separate cost denominators

For [PR #278](https://github.com/SoupTeam/soup-wall/pull/278), candidate
`7487981a67c6d27fc661cec9b6fbfcb1b9581619` had parents
`be5086fea80f39205d18a20adb0ba76928d3b649` (base) and
`730746e8a727378d386d41df9e8f60cb34fb3273` (head). GitHub's retained
[commit-status API](https://api.github.com/repos/SoupTeam/soup-wall/commits/7487981a67c6d27fc661cec9b6fbfcb1b9581619/statuses)
shows this sequence on October 26, 2026 (UTC):

| Time | Status ID | Decision |
| --- | ---: | --- |
| 20:35:02 | 57305589790 | pending: checking exact-source CI evidence |
| 20:35:23 | 57305622776 | success: selected jobs and five CodeQL analyses passed |
| 20:39:14 | 57305981046 | pending: checking the same candidate again |
| 20:39:41 | 57306023091 | success again |

These are **four status writes and two successful verification passes**, not
four CI suites. The second pending interval lasted 27 seconds. This timeline
does not establish a bypass or a billed-runner saving. The concurrent
`workflow_run` queue also contains runs for other PRs, so its count is not a
valid denominator for #278 alone.

The deterministic API fixture in `test_ci_admission_reuse.py` has one Ready PR,
one central CI run, one managed CodeQL run and nine required job records
(planner, documentation, two component members and five CodeQL analyses).
After the first full successful verification, **one duplicate completion** has
the following measured logical API operations:

| Mode | GET | Paginated-list calls | POST | Total | Direct required-job GET | Status writes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Full verifier, switch off | 17 | 7 | 2 | 26 | 9 | pending, success |
| Verified identical receipt | 17 | 7 | 0 | 24 | 9 | none |

Thus this nine-job fixture saves 2/26 logical calls (7.7%) and prevents
2/2 redundant status transitions. A paginated-list call represents one page
in this fixture; production lists can require more pages. **Both modes still
allocate one workflow runner for the duplicate event.** No billed minutes,
network byte savings or full-suite cost reduction is claimed from this mocked
measurement. Production before/after measurements must count actual verifier
jobs, API requests and status writes independently of central CI and CodeQL.
The trusted verifier prints only finite GET/POST/status-write attempt counts,
including HTTP retries, to make that later comparison possible without
logging a token, URL query body, job output or private payload.

## Evidence identity and refusal behavior

On a full success, the verifier may put a SHA-256 evidence receipt in the
existing status's `target_url`. It contains no token, PR output or raw job log.
The receipt identifies the trusted verifier revision, Ready PR update epoch,
base/head and
test-merge parents, changed paths, activation/ruleset identity, selected
support plan, selected workflow IDs and attempt numbers, and every required
job/CodeQL analysis ID, source, status and conclusion. The linked successful
verifier run must be the trusted `ci-admission.yml` on that revision and
attempt. A status from another context, actor, run or revision is not reusable.

A duplicate first reads the latest status. It then **freshly** inspects the
candidate: current PR and merge parents, live activation and selection,
selected attempt job lists, **every required individual job detail**, all five
CodeQL analyses, direct selected-run details, a second run listing and final PR
state. This is necessary because an attempt list and an individual job detail
can temporarily disagree. Reuse only skips redundant status writes when the
freshly read required identities and conclusions match the previous full
verification exactly. It publishes no new success and does not replace the
prior success with a temporary pending status. If any
identity differs or the receipt/API is unavailable, it takes the ordinary full
path, posts pending, reads individual job details and can only publish success
after all existing checks pass.

An `in_progress` CI/CodeQL event still suspends the old green status before
completion inspection. New attempts, failed/skipped/duplicate/missing required
jobs, an absent analysis, Draft transition and head/base/merge replacement
cannot reuse it. The final independent source and attempt checks remain in
both paths. A cancelled verifier has no successful run provenance for reuse;
its pending status remains blocking until a trusted re-evaluation. This is an
optimization of proven unchanged evidence, not a grace period or a cached
authorization to merge.

The workflow deliberately retains `cancel-in-progress: false` and its full
pending-event queue. Cancelling a queued writer could discard the only
invalidation event after a selected rerun starts. This narrow change reduces
status/API writes; it does **not** claim to coalesce workflow allocations or
shorten the full job-detail verifier. That limit is intentional until a
separate design can prove safe eager invalidation before any queue reduction.

## Maintainer control and qualification

1. Review the source and run the focused admission tests on the candidate.
   Keep `SOU160_ADMISSION_REUSE` absent during the Draft stage. Required
   checks, CodeQL thresholds, ruleset and runner settings stay unchanged.
2. After trusted code reaches default branch, use a disposable controlled PR
   with one harmless documentation change. Record its exact base, head,
   merge candidate, selected run IDs/attempts and five CodeQL analyses.
   Enable the repository variable only under maintainer control for this
   rollout, after the controlled baseline success is established. A duplicate
   completion should leave the same success status ID in place and emit the
   `unchanged current evidence already verified` diagnostic. Record actual
   verifier job durations/API and status counts before and after. Close the
   controlled PR without merge.
3. On that controlled candidate, exercise a new selected attempt and a Draft
   transition: the required context must go pending immediately. Preserve
   failed attempts. The deterministic tests cover changed parents, missing
   analysis, failed/duplicate jobs, lost verifier and API errors without
   manipulating protected branches or CodeQL configuration.
4. Roll back by removing `SOU160_ADMISSION_REUSE`. Every subsequent event
   uses the original full verifier path. The required context and its existing
   fail-closed rules are unaffected. Only the team lead performs final
   production enablement and merge.

The switch must not be enabled merely because a Draft fast check passes.
Current-source Ready CI, managed CodeQL, trusted admission and a controlled
positive/negative run are separate acceptance requirements.
