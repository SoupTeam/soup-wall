# SOU-97 candidate evidence (Increment 2): offline classification only

This evidence compares the candidate `rule_baseline/pilot_readonly_v1` with each profile's currently
selected classifier, on the matrix that was frozen in `f8e7a2e` and on the unchanged public
fixtures. No expectation, fixture, evaluator, policy, driver or CI file changed.

**This is not runtime acceptance.** It contains no native policy verdict, no real MCP server, no
Linux run, no execution effect and no latency. These are development numbers on public synthetic
data with provisional labels. Host: Windows-11-10.0.22631-SP0, Python 3.12.10.

## Identities

| Item | sha256 |
|---|---|
| Candidate `rule_baseline/pilot_readonly_v1/rule_baseline.py` | `82a41dded79cf560cefc5ab6894e9f247d31fec2992b2b7b6d0fcad02c0494f4` |
| Before, filesystem: frozen `rule_baseline/rule_baseline.py` | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| Before, Git: `rule_baseline/git_readonly_v1/rule_baseline.py` | `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474` |
| Matrix `soup_pilot_readonly_matrix_v0.1.json` | `3d19281c56d0c330761a36289b50c1df524a28c63bad88392ca85b94faf7da36` |
| `eval/eval_runner.py` (committed LF bytes) | `86dded74283e7dc38e3ea8b2996a8cccf900912ccb847ea0fdad482abcbd0662` |

The "before" results are the Increment 1 files in `../baseline/`, which are not re-run here.

## Matrix: before and after (`comparison.json`)

| Profile | Before | After | Newly failing | New risky misses | New technical failures | New benign false interruptions |
|---|---|---|---|---|---|---|
| filesystem | 51/73 | 65/73 | none | none | none | none |
| git | 27/40 | 27/40 | none | none | none | none |

**Filesystem.** 14 cases newly pass, and these are the only cases whose core output changed:
- PMF-B27 to B34 (`directory_tree`);
- PMF-B18, B19, B41, B42 (arrays of 201 to 256 items, above the 200-value walker bound);
- PMX-E01 (`directory_tree` with JSON-string arguments);
- PMF-M03 (`directory_tree` with a misleading description; unreachable under the pinned manifest).

Admitted-benign false interruptions go from 12 to 0.

**Git.** No core output changed, and the output is byte-identical to `git_readonly_v1` (see
`rule_baseline/test_pilot_readonly.py` Parity).

**Pending cases.** No unscored case changed its core output.

## Failures that remain (all also failing before)

- **Filesystem:**
  - PMF-R08 to R11: profile-refused forms. These are an empty path, `/`, and two 257-item arrays,
    and the candidate abstains on all four exactly as the baseline did.
  - PMF-U05: `move_file` misses `delete`. This is a risky miss.
  - PMF-V01 to V03: D06 failures masked as classifications.
- **Git:**
  - PMG-R01 to R09: profile-refused forms.
  - PMG-U03 (`git_reset`) and PMG-U04 (`git_checkout`): `unknown`, write not predicted. These are
    risky misses.
  - PMG-U07: `git_branch` returns `unknown`.
  - PMG-V01: D06 failure masked as a classification.

None of these is relabelled or hidden. The risky misses involve unsupported tools that the selected
profiles refuse before dispatch, so this increment does not change them.

## Existing public fixtures

Every case has the same outcome and core output as both frozen and `git_readonly_v1`:
- v0.4: 21/21
- v0.5: 23/26
- challenge v0.2: 29/35, critical CU02
- mixed v0.1 + benign v0.1: 5/5

## Reproduce

Export the committed `eval/eval_runner.py` and the fixtures as in `../baseline/README.md`, plus
`rule_baseline/pilot_readonly_v1/rule_baseline.py`. Then:

```sh
python3 -B eval/eval_runner.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json \
  --classifier-path rule_baseline/pilot_readonly_v1 --out-dir out/matrix
# public: the same four runs as the baseline README, with --classifier-path rule_baseline/pilot_readonly_v1
python3 -I -B <repo>/eval/evidence/sou97/candidate/compare_view.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json \
  <repo>/eval/evidence/sou97/baseline/frozen/matrix/results.json \
  <repo>/eval/evidence/sou97/baseline/git_readonly_v1/matrix/results.json out/matrix/results.json
```
