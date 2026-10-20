# SOU-85 original workspace acceptance

Scope: scripted offline controls of original AgentDojo functions/evaluators and
the actual Agent daemon. No external provider calls or Phase 4 effectiveness claim.
Reproduction is in [native admission](../../native-admission.md#offline-reproduction).

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
