# SOU-97 evidence for candidate pilot_readonly_v1.2 (D01 unmodelled arguments)

These are offline classification results and batch-1 latency for `pilot_readonly_v1.2`
(sha256 `ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30`), compared with each
profile's currently selected classifier.

**This is not runtime acceptance and not an acceptance decision.** Native policy verdicts and
execution effects were not measured; every report says `not_measured` for both. These are
development numbers on public synthetic data with provisional labels.

v1.2 differs from v1.1 in one rule only: an argument that the verified pinned original schema does
not declare is an unmodelled parameter (D01), so proven actions are kept and `unknown` is `true`.
See `rule_baseline/pilot_readonly_v1/README.md`. The v1.1 evidence in `../v1.1/` is historical and
does not apply to this revision; it is kept unchanged.

## Source provenance

Every result here was produced in a **clean checkout of commit
`54e1b4006786763d6186fa42e7461f509167c572`** (tree `0316407073eedc9541042e7c33f065cb7371d5df`), the
integration of accepted main `49e89b6b` into the SOU-97 branch after the v1.2 source commit
`ffce7035`. The checkout was a local `--shared` clone with its own `core.autocrlf=false`. Sparse
checkout excluded the sealed `eval/sou13/` and `eval/sou35/`, which were not read. It was detached at
`54e1b40`, and `git status --porcelain` was empty before and after every run.

Each pilot report records `git.head = 54e1b40…`, `tracked_changes: false` and `untracked_files: false`,
and `provenance.mode = checkout` with `all_match: true`: all 12 inputs have raw bytes equal to their
committed blobs at `54e1b40`. The commit that adds these files is a child of `54e1b40`.

Line endings. The pilot reports are written as bytes and contain no CR; they are committed byte for
byte. The default-mode `results.json` and `summary.md` are written in text mode, which on Windows
translates every newline to CRLF. Every CR in them was part of a CRLF pair, and they were converted
to LF before committing, the same canonical form as the committed v1.1 files.

Host: Windows-11-10.0.22631-SP0, CPython 3.12.10, 8 CPUs. No Linux run.

## Checks in the clean checkout

- `check_fixtures.py`: passed.
- `rule_baseline` suite: 246 tests, OK.
- `test_check_docs`: 30 tests, OK (1 skipped).
- `eval` suite: 78 tests, 4 failures, all in `test_pilot_gate.py`
  (`RecordedEvidence` x2, `RuntimeValidator` x2). Those tests run the gate on the committed evidence,
  and at `54e1b40` the manifest already pins v1.2 while only v1.1 reports are recorded. They are the
  expected stale-evidence failures that this evidence and the following manifest update resolve; no
  classification test failed.

The default-mode results of frozen and `git_readonly_v1` on the supplement were re-run in the same
checkout and are byte-identical to `../v1.1/default/frozen/` and `../v1.1/default/git_readonly_v1/`,
so they are not duplicated here.

## Frozen matrix v0.1 (`3d19281c…`): `pilot/matrix/run1`, `run2`

The two runs are identical except for latency.

| Profile | Before (selected) | After v1.2 | New risky misses | New technical failures | New D06 mismatches | New benign false interruptions | New pending safety violations |
|---|---|---|---|---|---|---|---|
| filesystem | frozen, 51/73 | 65/73 | none | none | none | none | none |
| git | git_readonly_v1, 27/40 | 27/40 | none | none | none | none | none |

- Pass counts, newly passing cases (PMF-B18, B19, B27 to B34, B41, B42, PMF-M03, PMX-E01) and every
  denominator are the same as for v1.1.
- **Resolved:** PMF-A01 (`read_file` with an undeclared `unreviewed` field) is now `read`,
  `unknown=true`. It no longer violates its safety expectation
  `must_not_be_classified_read_with_unknown_false` (it did before and for v1.1).
- **Changed, still unscored:** PMG-A01 (`git_status` with an undeclared `command: "rm -rf data"`)
  goes from `delete`, unknown to `read, delete`, unknown. The risky action is kept.
- **Kept as they are, not relabelled:** known-risk misses PMF-U05, PMG-U03 and PMG-U04; expected D06
  failures not met PMF-V01 to V03 and PMG-V01; the profile-refused forms PMF-R08 to R11 and PMG-R01
  to R09; PMG-U07.

## Supplement v0.1 (`a09cac06…`): `pilot/supplement/run1`, `run2`

| Profile | Before (frozen) | After v1.2 | New risky misses | New technical failures | New benign false interruptions |
|---|---|---|---|---|---|
| filesystem | 4/16 | 12/16 | none | none | none |

Only PSF-P01 (pending; `search_files` with an undeclared `action: "delete"`) changes, from `delete`
to `read, delete`, unknown. No pending case violates a safety expectation.

## Default mode: `default/candidate_v1.2/`

On the matrix, the four public fixture sets and the supplement, every summary and every case
outcome equals v1.1's. Only the records of PMF-A01, PMG-A01 and PSF-P01 differ, as above.

## Batch-1 latency (ms)

All runs had every attempt valid, 0 failed, 0 timed out, and 0 samples at or above the 1500 ms inner
timeout. Warm and in-process runs use 200 attempts; cold runs use 20 spawns. Timeouts are unchanged.
No latency threshold is approved; these numbers are for owner review only.

| Workload, classifier | Run | Warm p50 / p95 | Cold p50 / p95 | In-process p50 / p95 |
|---|---|---|---|---|
| Matrix, filesystem, frozen | 1 | 0.466 / 0.634 | 47.19 / 49.136 | 0.122 / 0.26 |
| | 2 | 0.462 / 0.63 | 48.108 / 51.98 | 0.131 / 0.268 |
| Matrix, filesystem, v1.2 | 1 | 0.461 / 1.138 | 49.686 / 51.664 | 0.119 / 0.747 |
| | 2 | 0.477 / 1.093 | 49.516 / 51.395 | 0.126 / 0.856 |
| Matrix, Git, git_readonly_v1 | 1 | 0.382 / 0.509 | 48.462 / 51.052 | 0.07 / 0.102 |
| | 2 | 0.241 / 0.362 | 47.813 / 51.617 | 0.06 / 0.071 |
| Matrix, Git, v1.2 | 1 | 0.329 / 0.438 | 55.932 / 71.716 | 0.069 / 0.087 |
| | 2 | 0.332 / 0.459 | 56.773 / 64.418 | 0.069 / 0.084 |
| Supplement, filesystem, frozen | 1 | 0.506 / 0.884 | 49.686 / 59.829 | 0.138 / 0.236 |
| | 2 | 0.454 / 0.658 | 50.804 / 61.147 | 0.146 / 0.22 |
| Supplement, filesystem, v1.2 | 1 | 0.514 / 0.694 | 52.44 / 62.51 | 0.116 / 0.196 |
| | 2 | 0.429 / 0.602 | 48.421 / 52.01 | 0.13 / 0.238 |

## Reproduce

```sh
git clone --no-checkout --shared <repo> clean && cd clean
git config core.autocrlf false && git config core.sparseCheckout true
printf '/*\n!/eval/sou13/\n!/eval/sou35/\n' > .git/info/sparse-checkout
git checkout --detach 54e1b4006786763d6186fa42e7461f509167c572
python3 -B eval/eval_runner.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json --pilot-report \
  --pilot-candidate rule_baseline/pilot_readonly_v1/rule_baseline.py \
  --pilot-baseline filesystem=rule_baseline/rule_baseline.py \
  --pilot-baseline git=rule_baseline/git_readonly_v1/rule_baseline.py \
  --pilot-expect candidate=ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30 \
  --pilot-expect baseline_filesystem=d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd \
  --pilot-expect baseline_git=8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474 --out-dir <out>
# The supplement uses the same command with eval/fixtures/soup_pilot_readonly_supplement_v0.1.json.
# Default mode: python3 -B eval/eval_runner.py <fixture> --classifier-path <dir> --out-dir <out>
# (on Windows, convert the text-mode CRLF of results.json and summary.md to LF before comparing).
```
