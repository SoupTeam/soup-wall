# SOU-97 pilot report (Increment 3A): offline classification and latency

These files are produced by the additive `eval/eval_runner.py --pilot-report` mode: two runs of the
same command on the same host. **They are not runtime acceptance and not an acceptance decision.**
Native policy verdicts and execution effects were not measured; the reports say `not_measured` for
both and never derive them from predictions. These are development numbers on the public synthetic
matrix that was frozen in `f8e7a2e`.

Host: Windows-11-10.0.22631-SP0, CPython 3.12.10, 8 CPUs. No Linux run.

The inputs were the committed blobs of this commit, exported with `git show :<path>`. The working
copies were not used, because a Windows `core.autocrlf` checkout of `git_readonly_v1` hashes
`cfae72…`. Pointed at that working copy with `--pilot-expect`, the runner refuses with exit 4
rather than normalizing. The export is not a git checkout, so the reports record `git.head: null`;
the source commit is the commit that adds these files, whose parent is `ef0d17b`. Every executed
byte is identified by sha256 in the `identities` and `classifiers` sections of each report.

## Command

```sh
python3 -B eval/eval_runner.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json --pilot-report \
  --pilot-candidate rule_baseline/pilot_readonly_v1/rule_baseline.py \
  --pilot-baseline filesystem=rule_baseline/rule_baseline.py \
  --pilot-baseline git=rule_baseline/git_readonly_v1/rule_baseline.py \
  --pilot-expect candidate=82a41dded79cf560cefc5ab6894e9f247d31fec2992b2b7b6d0fcad02c0494f4 \
  --pilot-expect baseline_filesystem=d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd \
  --pilot-expect baseline_git=8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474 \
  --out-dir <out>          # defaults: --latency-calls 200 --latency-spawns 20
```

## Reproducibility

The two runs are identical except for the `latency` objects (checked by comparing the parsed JSON
without those keys). Both exited 0 and passed the drift check.

## Results (run1; run2 agrees on everything except timing)

| Profile | Before (selected) | After (candidate) | New risky misses | New technical failures | New D06 mismatches | New benign false interruptions |
|---|---|---|---|---|---|---|
| filesystem | frozen, 51/73 | 65/73 | none | none | none | none |
| git | git_readonly_v1, 27/40 | 27/40 | none | none | none | none |

- **Filesystem:** supported benign false interruptions go from 12/46 to 0/46. Abstentions on
  known-effect cases go from 18/69 to 4/69; the remaining four are the profile-refused forms
  PMF-R08 to R11.
- **Kept as they are, not relabelled:**
  - known-risk misses PMF-U05 (`move_file` misses `delete`), PMG-U03 and PMG-U04;
  - expected D06 failures not met: PMF-V01, V02, V03 and PMG-V01, all masked as classifications;
  - the single mixed-action case PMF-U05, which fails both before and after.
- **Per-action counts:** precision, recall, TP/FP/FN and denominators are in each report.

Batch-1 latency, run1, in ms (all attempts valid; 0 failed; 0 timed out; 0 at or above the 1500 ms
inner timeout):

| Profile, classifier | warm p50 / p95 | cold p50 / p95 | in-process p50 / p95 |
|---|---|---|---|
| filesystem, frozen | 0.281 / 0.533 | 58.81 / 68.968 | 0.157 / 0.361 |
| filesystem, candidate | 0.421 / 1.71 | 64.395 / 70.715 | 0.143 / 1.432 |
| git, git_readonly_v1 | 0.273 / 0.373 | 61.763 / 71.217 | 0.074 / 0.088 |
| git, candidate | 0.199 / 0.356 | 65.05 / 70.019 | 0.09 / 0.102 |

Warm and in-process runs use 200 attempts; cold runs use 20 spawns. The workloads are the
profile's admitted cases: 46 for filesystem, 20 for Git. The candidate's higher filesystem p95
reflects the proof's per-item checks on arrays of up to 256 items. No latency threshold has been
approved; these numbers are reported for owner review only. Worker deadlines and evaluator timeouts
are unchanged: the bridge inner timeout stays 1500 ms and the request timeout 5.0 s.
