# SOU-153 public scripted workspace run

The original matched/1 producers executed the frozen SOU-36 public development
selection using distinct clean revisions, the original upstream task and
injection evaluators, and one identical loopback provider. Each side completed
16/16 planned matched pairs (32 trajectories, 64 loopback responses).
The provider issued one fixed read-only `list_files` request, then a fixed final
response. It exercised the real tool runtime and evaluator interface. The user
tasks require task-specific behavior that this script does not attempt.

| Side | Revision | Runtime |
| --- | --- | --- |
| Baseline | `6fe98d71fc2b806d996ec0ca493f20f4d9da2202` | Hook fallback |
| Candidate | `ad41af500710450e8f1697da57eafdf5571301fa` | Native workspace registry |

Both enforced sides record 0/8 benign utility, 0/8 attacked utility, 0/8
attack objectives attained and 0/8 benign interruptions. All recorded paired
outcomes are unchanged. The published tasks and injection content enter the
original environment, but the script does not use them to choose actions.
These outcomes characterize only that scripted workload.

The [offline comparison](report.md) returns `conditionally_comparable`. It
verifies the run-to-plan hashes, pinned 112-file upstream inventory and
injection hashes. The producer still lacks an inventoried per-case manifest
binding the full task and environment bytes, expected labels and semantic
families. The approved family interval is unavailable, and the plan contains
at most 4.57 effective dependency clusters even before any families merge
them. Unknown evaluator outcomes and individual timeouts cannot be resolved
by matched/1. The original reports and comparison retain these limits.
DEC-SOU153-20261028 remains open for the missing per-case and family binding.

## Replay

With the retained `inputs.json` from the operator evidence bundle, use the
unchanged comparator from the repository root:

```sh
E=docs/benchmarks/evidence/sou153-public-runtime
python3 -B scripts/benchmarks/paired_regression.py \
  --baseline-plan "$E/baseline-plan.json" --baseline-run "$E/baseline-run.json" \
  --candidate-plan "$E/candidate-plan.json" --candidate-run "$E/candidate-run.json" \
  --inputs /private/sou153/inputs.json --out-dir /private/sou153/replay
```

[Run receipt](run-receipt.json) binds the measured source/tree, toolchain,
binary, policy, plans and reports. The run can be reproduced from the pinned
public AgentDojo revision and the checkout pair with the [recorded loopback runner](../../../../scripts/benchmarks/run-public-agentdojo-pair.py). The published aggregate remains qualified by the gaps above.
