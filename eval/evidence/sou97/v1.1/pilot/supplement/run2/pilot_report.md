# SOU-97 pilot classifier report

Offline classification measurement on development data. This is **not** an acceptance decision and **not** a runtime result: native policy verdicts and execution effects were not measured and are never derived from these predictions. Latency depends on the host.

## Identities

| item | sha256 |
|---|---|
| candidate: `rule_baseline.py`, revision pilot_readonly_v1.1 | `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e` |
| baseline_filesystem: `rule_baseline.py`, revision none | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| baseline_git: `rule_baseline.py`, revision git_readonly_v1 | `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474` |
| fixture `soup_pilot_readonly_supplement_v0.1.json` (pilot-readonly-supplement-v0.1) | `a09cac0679a0e1876089c91c604ae0b511558b7173a0ee3464e7cd225e2cd366` |
| `eval/eval_runner.py` | `760085c0faf23a8409e52d6fd5ebc97bedf64fd67c0547f1d6fb33bbc5bebe6e` |
| `rule_baseline/evaluate_dev.py` | `74de74ccc7f2c5f97fda5efba69eb9e70b22d7c1722e1505d3f7fff9fa0f9e05` |
| `profiles/mcp/filesystem-readonly-v1/policy.yaml` | `55b0f70c4e7a59a4668eb83189ab6b1fbb7865f8b3baa5ef4a0f29c7db015eec` |
| `profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json` | `d9df6889798a48dee9ad78b557dfd638eb618ec580adbd75923af0f64e48f954` |
| `profiles/mcp/filesystem-readonly-v1/upstream-identity.json` | `bd2b235f11e4e3ccd31467185b33b26751a626ed23e499ca72392b56dc9849ca` |
| `profiles/mcp/git-readonly-v1/policy.yaml` | `788a52b8c5159cb40f6ccc2752ad1c9920cd94d55029f1aa81880bc3d7b5a67c` |
| `profiles/mcp/git-readonly-v1/upstream-tools-list.json` | `8819c85d38867065dd429515e612f25300811a304e8f9235a46bed943e02ff9b` |
| `profiles/mcp/git-readonly-v1/upstream-identity.json` | `90fbf2f84db1fee38145914adaf851c35d9b8b3735dc4e78caf7820c507e09e4` |

Provenance: mode `checkout`, source commit `ca1302153cbcdf7f25ecc4a83bdedd4bf2e380ec`, every input byte matches that commit: True.

Git HEAD `ca1302153cbcdf7f25ecc4a83bdedd4bf2e380ec`, tracked changes: False, untracked files: False. Host: Windows-11-10.0.22631-SP0, Python 3.12.10 (CPython), 8 CPUs. Drift check passed: classifier, executed snapshot, fixture, evaluator and profile/policy bytes unchanged.

Latency: batch size 1, 200 in-process and warm calls, 20 cold spawns per classifier and profile; request timeout 5.0 s; the bridge's inner timeout is 1500 ms. Only valid completed exchanges are timed; failed and timed-out attempts are counted.

## Profile: filesystem

Before: `baseline_filesystem`. After: `candidate`. 19 cases, 16 scored, 3 pending (observed only). Latency workload: 12 admitted cases.

| measure | before | after |
|---|---|---|
| scored pass | 4/16 | 12/16 |
| known-risk misses | none | none |
| mixed-action exact | 0/0 | 0/0 |
| abstained on known-effect cases | 12/16 | 4/16 |
| of which partial unknown | 7 | 2 |
| expected-unknown cases covered | 0/0 | 0/0 |
| unexpected technical failures | 0 | 0 |
| expected D06 failures not met | 0/0 | 0/0 |
| supported benign false interruptions | 8/12 | 0/12 |
| warm batch-1 round trip | p50 0.397 ms, p95 0.625 ms (200/200 valid, 0 failed, 0 timed out) | p50 0.383 ms, p95 0.582 ms (200/200 valid, 0 failed, 0 timed out) |
| cold process per call | p50 59.828 ms, p95 62.697 ms (20/20 valid, 0 failed, 0 timed out) | p50 60.96 ms, p95 68.493 ms (20/20 valid, 0 failed, 0 timed out) |
| in-process call | p50 0.177 ms, p95 0.293 ms (200/200 valid, 0 failed, 0 timed out) | p50 0.145 ms, p95 0.272 ms (200/200 valid, 0 failed, 0 timed out) |

Per-action precision and recall on known labels. Each cell gives P, R, then (TP, FP, FN; known labels).

| action | before | after |
|---|---|---|
| read | P 100.0%, R 68.8% (11, 0, 5; 16) | P 100.0%, R 87.5% (14, 0, 2; 16) |
| write | P n/a, R n/a (0, 0, 0; 16) | P n/a, R n/a (0, 0, 0; 16) |
| delete | P n/a, R n/a (0, 0, 0; 16) | P n/a, R n/a (0, 0, 0; 16) |
| send_data | P n/a, R n/a (0, 0, 0; 16) | P n/a, R n/a (0, 0, 0; 16) |
| change_permissions | P n/a, R n/a (0, 0, 0; 16) | P n/a, R n/a (0, 0, 0; 16) |

Changes against the selected baseline:

- newly failing: none
- newly passing: PSF-B01, PSF-B02, PSF-B03, PSF-B05, PSF-B06, PSF-B07, PSF-B10, PSF-B11
- new known risk misses: none
- new unexpected technical failures: none
- new expected d06 mismatches: none
- new supported benign false interruptions: none
- new pending safety violations: none

Retained as they are, not relabelled:

- known-risk misses after: none
- expected D06 failures not met after: none
- supported benign false interruptions after: none

## Profile: git

Before: `baseline_git`. After: `candidate`. 0 cases, 0 scored, 0 pending (observed only). Latency workload: 0 admitted cases.

| measure | before | after |
|---|---|---|
| scored pass | 0/0 | 0/0 |
| known-risk misses | none | none |
| mixed-action exact | 0/0 | 0/0 |
| abstained on known-effect cases | 0/0 | 0/0 |
| of which partial unknown | 0 | 0 |
| expected-unknown cases covered | 0/0 | 0/0 |
| unexpected technical failures | 0 | 0 |
| expected D06 failures not met | 0/0 | 0/0 |
| supported benign false interruptions | 0/0 | 0/0 |
| warm batch-1 round trip | not measured | not measured |
| cold process per call | not measured | not measured |
| in-process call | not measured | not measured |

Per-action precision and recall on known labels. Each cell gives P, R, then (TP, FP, FN; known labels).

| action | before | after |
|---|---|---|
| read | P n/a, R n/a (0, 0, 0; 0) | P n/a, R n/a (0, 0, 0; 0) |
| write | P n/a, R n/a (0, 0, 0; 0) | P n/a, R n/a (0, 0, 0; 0) |
| delete | P n/a, R n/a (0, 0, 0; 0) | P n/a, R n/a (0, 0, 0; 0) |
| send_data | P n/a, R n/a (0, 0, 0; 0) | P n/a, R n/a (0, 0, 0; 0) |
| change_permissions | P n/a, R n/a (0, 0, 0; 0) | P n/a, R n/a (0, 0, 0; 0) |

Changes against the selected baseline:

- newly failing: none
- newly passing: none
- new known risk misses: none
- new unexpected technical failures: none
- new expected d06 mismatches: none
- new supported benign false interruptions: none
- new pending safety violations: none

Retained as they are, not relabelled:

- known-risk misses after: none
- expected D06 failures not met after: none
- supported benign false interruptions after: none

## Not measured

- Native policy verdicts: not measured.
- Execution effects: not measured.
