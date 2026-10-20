# SOU-85 original workspace acceptance

Scope: scripted offline controls of original AgentDojo functions/evaluators and
the actual Agent daemon. No external provider calls or Phase 4 effectiveness claim.
Reproduction is in [native admission](../../native-admission.md#offline-reproduction).

## Measured source and outcome

[Selected Linux CI run](https://github.com/SoupTeam/soup-wall/actions/runs/39416337529)
tested source `ad41af500710450e8f1697da57eafdf5571301fa`, including accepted main
`372284fee1313389dfb91cb14c3a75fa83d5b6ea`.
Later evidence-only commits do not change the tested implementation.

- [Workspace report](report.json): **146/146 assertions**, zero hidden skips.
  Every one of the 24 original inventory functions has an explicit daemon
  control; 21 have reviewed supported argument semantics and three explicitly
  refuse environment-derived calendar notification destinations.
- [Legacy schema-1 fixture](legacy-native.json): **26/26 tests**, zero skips.
  Its seven provider requests went only to an owned scripted loopback fixture;
  external model/provider calls were zero.
- Rust workspace-profile tests: **4/4**; Python profile/schema tests: **4/4**.
  Rust formatting, 23 adapter unit tests and the existing local Gateway smoke
  also passed in that selected run.
- [Exact generated registry](registry.json) is bound by SHA-256 in the report.
  The report also binds original upstream inventory/license, dependency lock,
  compiled adapter sources, profile, shipped policy and actual Agent binary.

Allowed read/create/append/delete effects, original errors and benign continuation
are independently witnessed. The nested control requires the exact child-call,
child-result, parent-call, parent-result and parent-context ordering and one
original execution of each function. Email and recipient-changing operations
retain the shipped policy's unattended Ask and zero original executions.
Distinctive untrusted resource reuse followed by deletion is Deny with no
original deletion. A withheld result can follow an already-completed effect.
Malformed final context stops the trajectory after original execution.

Original user/attack evaluators are calibrated on known positive and negative
states; these are not model utility or attack-prevention scores. Incomplete
trajectories never receive evaluator outcomes.

## Scope and remaining coverage

The controls exercise the original pinned in-memory benchmark environments.
They do not demonstrate arbitrary network/filesystem containment, every task
trajectory, live models, held-out effectiveness or recovery after refusal.
Event attachments, implicit calendar recipients and delegated-host execution
remain unsupported. There is no native human-approval continuation channel.
The generated development proposal remains unapproved and is retained in the CI
artifact; no plan was frozen and no model/cost/threshold approval was inferred.

Local Windows benchmark discovery passed 47 tests with 19 explicit runtime
skips; the selected Linux native fixture above executes its 26 tests without
skips. The broader pre-refresh Windows scripts run had 939 tests: 809 passed,
120 skipped and ten failures/errors in POSIX/TLS/path and unrelated fixture
checks. It is not qualification and no failure was suppressed. Full PR
qualification is separate from the selected source run linked above.

## Retained initial failure

[Attempt 1](attempt-1.json) is the unchanged failed report from source
`c2892e6d0ba7bd7889799bff693dffbf2e6f434b`,
[manual CI run](https://github.com/SoupTeam/soup-wall/actions/runs/39411432221).
The build and four native profile unit tests passed. The initial scripted
expectation incorrectly assumed that an allowlisted email destination would
Allow. The shipped `ask-pii-egress` rule also applies to recipient addresses.
That expectation was corrected to require the policy's Ask and zero original
executions, with explicit reason-code evidence. The upstream send effect is
calibrated separately without protection. Policy and historical benchmark
labels were not changed.

The initial run is not acceptance. Subsequent exact-source evidence is retained
in the `agentdojo-workspace-offline` CI artifact while implementation continues.

## Retained context-control failure

[Attempt 2](attempt-2.json), source
`733916f66d46ef0441a583d2a69cebfb01e99f14`,
[CI run](https://github.com/SoupTeam/soup-wall/actions/runs/39412080807),
passed the email refusal controls and result withholding. Its context control
incorrectly expected a policy verdict for an invalid original call ID. The
daemon instead refused the context envelope after the original function and
result admission. The corrected control requires that exact context failure,
one original execution, and a stopped trajectory. It does not claim an injection
detector verdict, task completion or prevented attack.

## Expanded-run setup failure

The expanded [run at 404d9e5](https://github.com/SoupTeam/soup-wall/actions/runs/39413880468)
passed its build and four Rust tests, then refused pre-existing temporary
inputs restored by the Rust target cache. No expanded workspace result was
produced. The procedure now accepts a fresh owned base directory, and CI selects
`RUNNER_TEMP` outside that cache. It still refuses an existing selected directory.
