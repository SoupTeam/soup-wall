# SOU-97 evidence for candidate pilot_readonly_v1.1 (Increment 3B)

These are offline classification results and batch-1 latency for `pilot_readonly_v1.1`
(sha256 `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e`), compared with each
profile's currently selected classifier.

**This is not runtime acceptance and not an acceptance decision.** Native policy verdicts and
execution effects were not measured; every report says `not_measured` for both. These are
development numbers on public synthetic data with provisional labels.

The evidence for the superseded `pilot_readonly_v1` (`82a41dde…`) in `../candidate/` and
`../pilot_report/` is historical and does not apply to this revision.

## Source provenance

Every result here was produced in a **clean checkout of commit
`ca1302153cbcdf7f25ecc4a83bdedd4bf2e380ec`**. The checkout was a local `--shared` clone with its own
`core.autocrlf=false`. Sparse checkout excluded the sealed `eval/sou13/` and `eval/sou35/`, which
were not read. It was detached at `ca13021`, and `git status --porcelain` was empty before and after
every run.

Each pilot report records `git.head = ca13021…`, `tracked_changes: false` and `untracked_files: false`,
and `provenance.mode = checkout` with `all_match: true`. That means all 12 inputs (classifiers,
fixture, runner, `evaluate_dev.py`, profile policies, tool lists and identities) have raw bytes equal
to their committed blobs at `ca13021`. The commit that adds these files is a child of `ca13021`.

Host: Windows-11-10.0.22631-SP0, CPython 3.12.10, 8 CPUs. No Linux run. Because drive C: was full,
all temporary files, including the cold- and warm-process latency snapshots, were on drive D:
(`TMP`/`TEMP` = `D:\soup-wall-sou97-tmp`).

## Checks in the clean checkout

All of these exited 0:
- `check_fixtures.py`;
- `rule_baseline` suite: 234 tests;
- `eval` suite: 57 tests;
- `test_check_docs`: 30 tests, 1 skipped.

`scripts/check_docs.py` exited 1 there, with 12 missing-link errors. Every one of them is a link into
the sealed directories the sparse checkout excludes. The full working tree reports 0 errors.

The default-mode results of frozen and `git_readonly_v1` on the matrix and public fixtures are
identical, case for case and in the summary, to `../baseline/`. On the matrix and every public
fixture, v1.1's core outputs and outcomes are identical to v1's (`../candidate/`).

## Frozen matrix v0.1 (`3d19281c…`): `pilot/matrix/run1`, `run2`

The two runs are identical except for latency.

| Profile | Before (selected) | After v1.1 | New risky misses | New technical failures | New D06 mismatches | New benign false interruptions | New pending safety violations |
|---|---|---|---|---|---|---|---|
| filesystem | frozen, 51/73 | 65/73 | none | none | none | none | none |
| git | git_readonly_v1, 27/40 | 27/40 | none | none | none | none | none |

- **Filesystem.**
  - Newly passing: PMF-B18, B19, B27 to B34, B41, B42, PMF-M03 and PMX-E01.
  - Supported benign false interruptions: 12/46 before, 0/46 after.
  - Unexpected technical failures: 0.
- **Kept as they are, not relabelled:**
  - known-risk misses PMF-U05 (`move_file` misses `delete`), PMG-U03 and PMG-U04;
  - expected D06 failures not met: PMF-V01, V02, V03 and PMG-V01, all masked as classifications;
  - the profile-refused forms PMF-R08 to R11 and PMG-R01 to R09, still abstained on;
  - PMG-U07 (`git_branch`, unknown).
- **Pending observation, present before and after.** PMF-A01 (`read_file` with an undeclared
  `unreviewed` field) is classified `read`, `unknown=false`. That violates its safety expectation
  `must_not_be_classified_read_with_unknown_false`. It comes from the inherited generic `read` verb
  rule, not from the new proof. The profile refuses the form (`refuse_schema`). The Increment 3A
  report also contained it, but I didn't call it out at the time.

## Supplement v0.1 (`a09cac06…`): `pilot/supplement/run1`, `run2`

The supplement holds long, multi-byte and control-character glob patterns (filesystem only) and is
reported separately. It was written together with v1.1, so unlike the matrix it was **not frozen
before** that candidate existed. Its expectations come from the profile validator and the pinned
upstream source.

| Profile | Before (frozen) | After v1.1 | New risky misses | New technical failures | New benign false interruptions |
|---|---|---|---|---|---|
| filesystem | 4/16 | 12/16 | none | none | none |

- Admitted benign false interruptions: 8/12 before, 0/12 after. The newly passing cases are
  PSF-B01, B02, B03, B05, B06, B07, B10 and B11.
- PSF-R01 to R04 (over 16 384 bytes, and a path with a control character) are refused by the
  profile; both classifiers abstain on them.
- The 3 pending cases (PSF-P01 to P03) violate no safety expectation.
- Default-mode results for `git_readonly_v1` on the supplement are also included (4/16; these are
  filesystem cases).

## Batch-1 latency (ms)

All runs had every attempt valid, 0 failed, 0 timed out, and 0 samples at or above the 1500 ms inner
timeout. Warm and in-process runs use 200 attempts; cold runs use 20 spawns. Timeouts are unchanged.
No latency threshold is approved; these numbers are for owner review only.

| Workload, classifier | Run | Warm p50 / p95 | Cold p50 / p95 | In-process p50 / p95 |
|---|---|---|---|---|
| Matrix, filesystem, frozen | 1 | 0.343 / 0.594 | 60.541 / 64.041 | 0.156 / 0.325 |
| | 2 | 0.339 / 0.591 | 59.377 / 63.743 | 0.163 / 0.327 |
| Matrix, filesystem, v1.1 | 1 | 0.377 / 1.111 | 60.909 / 71.03 | 0.15 / 1.028 |
| | 2 | 0.298 / 1.466 | 60.659 / 64.911 | 0.142 / 1.033 |
| Matrix, Git, git_readonly_v1 | 1 | 0.222 / 0.355 | 63.057 / 69.146 | 0.083 / 0.134 |
| | 2 | 0.343 / 0.476 | 60.233 / 64.228 | 0.073 / 0.127 |
| Matrix, Git, v1.1 | 1 | 0.332 / 0.441 | 61.86 / 65.45 | 0.077 / 0.089 |
| | 2 | 0.228 / 0.35 | 65.606 / 70.725 | 0.086 / 0.147 |
| Supplement, filesystem, frozen | 1 | 0.361 / 0.614 | 59.571 / 66.534 | 0.18 / 0.359 |
| | 2 | 0.397 / 0.625 | 59.828 / 62.697 | 0.177 / 0.293 |
| Supplement, filesystem, v1.1 | 1 | 0.402 / 0.645 | 61.191 / 66.43 | 0.147 / 0.264 |
| | 2 | 0.383 / 0.582 | 60.96 / 68.493 | 0.145 / 0.272 |

Compared with the v1 runs in `../pilot_report/` (same host; temp then on C:), the filesystem matrix
warm p95 is 1.111 and 1.466 ms for v1.1, against 1.71 and 1.618 ms for v1. The cold p95 values are
all in the 63 to 72 ms range. The p95 increase of the proof over the frozen baseline is about 0.5 to
1 ms on warm and in-process calls.

## Reproduce

```sh
git clone --no-checkout --shared <repo> clean && cd clean
git config core.autocrlf false && git config core.sparseCheckout true
printf '/*\n!/eval/sou13/\n!/eval/sou35/\n' > .git/info/sparse-checkout
git checkout --detach ca1302153cbcdf7f25ecc4a83bdedd4bf2e380ec
python3 -B eval/eval_runner.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json --pilot-report \
  --pilot-candidate rule_baseline/pilot_readonly_v1/rule_baseline.py \
  --pilot-baseline filesystem=rule_baseline/rule_baseline.py \
  --pilot-baseline git=rule_baseline/git_readonly_v1/rule_baseline.py \
  --pilot-expect candidate=9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e \
  --pilot-expect baseline_filesystem=d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd \
  --pilot-expect baseline_git=8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474 --out-dir <out>
# The supplement uses the same command with eval/fixtures/soup_pilot_readonly_supplement_v0.1.json.
# Default mode: python3 -B eval/eval_runner.py <fixture> --classifier-path <dir> --out-dir <out>
```
