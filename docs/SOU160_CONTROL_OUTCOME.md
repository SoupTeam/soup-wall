# SOU-160 controlled admission reuse outcome

Decision proposed on October 28, 2026: **stop the reuse rollout and keep the
switch off**. The reviewed implementation from [PR #284](https://github.com/SoupTeam/soup-wall/pull/284)
remains on `main`, but the controlled run did not reduce total API requests or
verifier runner time. The team lead owns the final issue decision. This record
does not claim that SOU-160 met its original cost objective.

## Exact control and denominators

The disposable [PR #285](https://github.com/SoupTeam/soup-wall/pull/285) was
closed without merge. Its only source change was a documentation file. Its
head was `8932cf2a2d6337b208abc4c21ce02d22225dcef7`, base was
`d57a8696a78adc39071e1783bcea63632efe21e4`, and test-merge candidate was
`6ac09f0ffa65b2b7ddf13e3ede701650cca93e1a`. The selected documentation
[CI run](https://github.com/SoupTeam/soup-wall/actions/runs/40514046816)
and all five analyses in the managed
[CodeQL run](https://github.com/SoupTeam/soup-wall/actions/runs/40514040246)
passed. The measured duplicate events below did not rerun that full CI or
CodeQL. Counts are physical HTTP attempts printed by the trusted verifier;
job time is the Actions job's `started_at` to `completed_at`, excluding queue
time. They do not measure network bytes or billed full-suite minutes.

| Unchanged-evidence completion | Verifier job | GET | POST | Total HTTP | Status writes | Job time | Required-status effect |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Reuse OFF | [40516517587 attempt 3, job 122236417476](https://github.com/SoupTeam/soup-wall/actions/runs/40516517587/attempts/3) | 47 | 2 | 49 | 2 | 30 s | Prior success was replaced by pending for 8 s, then a new success. |
| Reuse ON | [40514308665 attempt 2, job 122312476830](https://github.com/SoupTeam/soup-wall/actions/runs/40514308665/attempts/2) | 49 | 0 | 49 | 0 | 33 s | Existing success `57384202725` and its evidence receipt remained in place. |

The ON seed was a **different** trusted verifier run:
[40516517587 attempt 4](https://github.com/SoupTeam/soup-wall/actions/runs/40516517587/attempts/4)
used 50 GET, 2 POST, two status writes and 31 s to establish the receipt.
Rerunning the seed run itself would change its attempt identity and could not
prove unchanged-evidence reuse. The ON duplicate log explicitly reports
`unchanged current evidence already verified`. These observations demonstrate
stable status, **not** fewer total API requests, fewer verifier jobs or less
runner time. The OFF and ON samples are one job each; their 30/33 s difference
must not be interpreted as a performance trend.

## Safety observations and limits

- A new selected documentation CI attempt changed the evidence. The trusted
  [handler](https://github.com/SoupTeam/soup-wall/actions/runs/40539598072)
  used 71 GET and 2 POST, wrote pending `57384658025`, then success
  `57384673911`. The subsequent
  [duplicate](https://github.com/SoupTeam/soup-wall/actions/runs/40539617026)
  used 49 GET and 0 POST. That seven-second CI rerun finished before the
  handler ran. It proves attempt-sensitive revalidation, not pending
  visibility throughout a running selected job.
- A Ready-to-Draft transition superseded green with pending `57384841949`.
  After the team lead removed the switch, an ordinary verifier kept the Draft
  candidate pending as `57385013112`. The team lead reported independent
  repository and available-organization variable readback after removal; a
  separate OFF Ready-positive rerun was not performed.
- The original OFF baseline encountered a real GitHub API discrepancy: its
  CodeQL run reported success while the direct Rust job detail remained
  `in_progress`. Admission stayed pending until a focused verifier-only retry
  saw complete job evidence. This is concrete evidence against omitting the
  direct required-job detail check. Other adverse cases have deterministic
  regressions; they were not all exercised as live production failures.

## Stop recommendation

Keep `SOU160_ADMISSION_REUSE` absent in repository and organization settings.
Do not repeat the closed control or enable the switch to manufacture a savings
claim. The current reuse path still allocates a hosted verifier for every
duplicate completion, and its status/provenance reads offset the two avoided
POSTs. The observed objective was status stability only.

Two apparent shortcuts lack a safety proof under the current contract:

1. GitHub's default
   [concurrency queue](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency)
   replaces an already-pending workflow run; `queue: max` retains pending
   invalidation events. Replacing or cancelling a queued writer could discard
   the only event that suspends stale success. GitHub also does not guarantee
   dispatch order. Splitting invalidation and completion into independent
   writer groups would need an atomic ordering mechanism before it could be
   safe.
2. Skipping current PR, selected-run/attempt, required-job or CodeQL detail
   reads would weaken the source and failure checks. The observed Rust job
   snapshot inconsistency shows why a successful aggregate run alone is not
   sufficient evidence. Event PR associations can also be absent or lag, so
   routing solely from those associations cannot replace current PR discovery.

A future proposal should be reviewed separately. It must first prove that
every new attempt, source change, Draft transition, failure and API outage
invalidates authority before any writer can be dropped; then demonstrate a
measured reduction in **actual verifier job starts or HTTP requests** on a new
disposable candidate, with a bounded rollback. Until such evidence exists,
retain the trusted full verifier and its existing required context, CodeQL
thresholds and runner policy.
