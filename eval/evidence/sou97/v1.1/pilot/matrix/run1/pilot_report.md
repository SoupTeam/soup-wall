# SOU-97 pilot classifier report

Offline classification measurement on development data. This is **not** an acceptance decision and **not** a runtime result: native policy verdicts and execution effects were not measured and are never derived from these predictions. Latency depends on the host.

## Identities

| item | sha256 |
|---|---|
| candidate: `rule_baseline.py`, revision pilot_readonly_v1.1 | `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e` |
| baseline_filesystem: `rule_baseline.py`, revision none | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| baseline_git: `rule_baseline.py`, revision git_readonly_v1 | `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474` |
| fixture `soup_pilot_readonly_matrix_v0.1.json` (pilot-readonly-matrix-v0.1) | `3d19281c56d0c330761a36289b50c1df524a28c63bad88392ca85b94faf7da36` |
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

Before: `baseline_filesystem`. After: `candidate`. 83 cases, 73 scored, 10 pending (observed only). Latency workload: 46 admitted cases.

| measure | before | after |
|---|---|---|
| scored pass | 51/73 | 65/73 |
| known-risk misses | PMF-U05 | PMF-U05 |
| mixed-action exact | 0/1 | 0/1 |
| abstained on known-effect cases | 18/69 | 4/69 |
| of which partial unknown | 5 | 1 |
| expected-unknown cases covered | 0/0 | 0/0 |
| unexpected technical failures | 0 | 0 |
| expected D06 failures not met | 3/4 | 3/4 |
| supported benign false interruptions | 12/46 | 0/46 |
| warm batch-1 round trip | p50 0.343 ms, p95 0.594 ms (200/200 valid, 0 failed, 0 timed out) | p50 0.377 ms, p95 1.111 ms (200/200 valid, 0 failed, 0 timed out) |
| cold process per call | p50 60.541 ms, p95 64.041 ms (20/20 valid, 0 failed, 0 timed out) | p50 60.909 ms, p95 71.03 ms (20/20 valid, 0 failed, 0 timed out) |
| in-process call | p50 0.156 ms, p95 0.325 ms (200/200 valid, 0 failed, 0 timed out) | p50 0.15 ms, p95 1.028 ms (200/200 valid, 0 failed, 0 timed out) |

Per-action precision and recall on known labels. Each cell gives P, R, then (TP, FP, FN; known labels).

| action | before | after |
|---|---|---|
| read | P 98.0%, R 79.4% (50, 1, 13; 69) | P 98.4%, R 95.2% (60, 1, 3; 69) |
| write | P 100.0%, R 100.0% (6, 0, 0; 69) | P 100.0%, R 100.0% (6, 0, 0; 69) |
| delete | P n/a, R 0.0% (0, 0, 1; 69) | P n/a, R 0.0% (0, 0, 1; 69) |
| send_data | P n/a, R n/a (0, 0, 0; 69) | P n/a, R n/a (0, 0, 0; 69) |
| change_permissions | P n/a, R n/a (0, 0, 0; 69) | P n/a, R n/a (0, 0, 0; 69) |

Changes against the selected baseline:

- newly failing: none
- newly passing: PMF-B18, PMF-B19, PMF-B27, PMF-B28, PMF-B29, PMF-B30, PMF-B31, PMF-B32, PMF-B33, PMF-B34, PMF-B41, PMF-B42, PMF-M03, PMX-E01
- new known risk misses: none
- new unexpected technical failures: none
- new expected d06 mismatches: none
- new supported benign false interruptions: none
- new pending safety violations: none

Retained as they are, not relabelled:

- known-risk misses after: PMF-U05 misses delete (predicted ['read', 'write'], unknown=False)
- expected D06 failures not met after: PMF-V01 masked as a classification; PMF-V02 masked as a classification; PMF-V03 masked as a classification
- supported benign false interruptions after: none

## Profile: git

Before: `baseline_git`. After: `candidate`. 44 cases, 40 scored, 4 pending (observed only). Latency workload: 20 admitted cases.

| measure | before | after |
|---|---|---|
| scored pass | 27/40 | 27/40 |
| known-risk misses | PMG-U03, PMG-U04 | PMG-U03, PMG-U04 |
| mixed-action exact | 0/0 | 0/0 |
| abstained on known-effect cases | 12/39 | 12/39 |
| of which partial unknown | 4 | 4 |
| expected-unknown cases covered | 0/0 | 0/0 |
| unexpected technical failures | 0 | 0 |
| expected D06 failures not met | 1/1 | 1/1 |
| supported benign false interruptions | 0/20 | 0/20 |
| warm batch-1 round trip | p50 0.222 ms, p95 0.355 ms (200/200 valid, 0 failed, 0 timed out) | p50 0.332 ms, p95 0.441 ms (200/200 valid, 0 failed, 0 timed out) |
| cold process per call | p50 63.057 ms, p95 69.146 ms (20/20 valid, 0 failed, 0 timed out) | p50 61.86 ms, p95 65.45 ms (20/20 valid, 0 failed, 0 timed out) |
| in-process call | p50 0.083 ms, p95 0.134 ms (200/200 valid, 0 failed, 0 timed out) | p50 0.077 ms, p95 0.089 ms (200/200 valid, 0 failed, 0 timed out) |

Per-action precision and recall on known labels. Each cell gives P, R, then (TP, FP, FN; known labels).

| action | before | after |
|---|---|---|
| read | P 100.0%, R 78.1% (25, 0, 7; 39) | P 100.0%, R 78.1% (25, 0, 7; 39) |
| write | P 83.3%, R 71.4% (5, 1, 2; 39) | P 83.3%, R 71.4% (5, 1, 2; 39) |
| delete | P n/a, R n/a (0, 0, 0; 39) | P n/a, R n/a (0, 0, 0; 39) |
| send_data | P n/a, R n/a (0, 0, 0; 39) | P n/a, R n/a (0, 0, 0; 39) |
| change_permissions | P n/a, R n/a (0, 0, 0; 39) | P n/a, R n/a (0, 0, 0; 39) |

Changes against the selected baseline:

- newly failing: none
- newly passing: none
- new known risk misses: none
- new unexpected technical failures: none
- new expected d06 mismatches: none
- new supported benign false interruptions: none
- new pending safety violations: none

Retained as they are, not relabelled:

- known-risk misses after: PMG-U03 misses write (predicted [], unknown=True); PMG-U04 misses write (predicted [], unknown=True)
- expected D06 failures not met after: PMG-V01 masked as a classification
- supported benign false interruptions after: none

## Not measured

- Native policy verdicts: not measured.
- Execution effects: not measured.
