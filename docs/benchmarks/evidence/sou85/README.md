# SOU-85 original workspace acceptance

Scope: scripted offline controls of original AgentDojo functions/evaluators and
the actual Agent daemon. No provider calls or Phase 4 effectiveness claim.
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
