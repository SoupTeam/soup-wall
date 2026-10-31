# SOU-97 unchanged-baseline evidence (Increment 1)

The public development matrix `eval/fixtures/soup_pilot_readonly_matrix_v0.1.json` and these baseline
results were committed **before any SOU-97 candidate classifier existed**. Nothing here measures a
candidate.

## Scope and limits

- **Classification only.** These are offline `eval/eval_runner.py` results. No native policy verdict,
  no real MCP server, no Linux runtime and no execution effect were measured. `expected_native` and
  `effect_witness` in the matrix are expectations for a later runtime run, not observations.
- **No latency.** Latency is not measured in this increment.
- **Development data.** The matrix is public and synthetic, and it is visible during candidate
  development. It is not a held-out result. Labels are `provisional` (from the contract), not human
  Gold.
- **Host.** Windows-11-10.0.22631-SP0, Python 3.12.10. Linux was not available locally (no WSL
  distribution installed).
- **Known baseline failures are kept.** No historical fixture was changed or relabelled.

## Identities

| Item | sha256 (committed LF bytes) |
|---|---|
| Source commit (parent of this evidence) | `77a3b611ba537f8ae33b7a0a981a59248503ba36` |
| `eval/eval_runner.py` | `86dded74283e7dc38e3ea8b2996a8cccf900912ccb847ea0fdad482abcbd0662` |
| `rule_baseline/rule_baseline.py` (frozen; filesystem pilot selection) | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| `rule_baseline/git_readonly_v1/rule_baseline.py` (Git pilot selection) | `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474` |
| `eval/fixtures/soup_pilot_readonly_matrix_v0.1.json` | `3d19281c56d0c330761a36289b50c1df524a28c63bad88392ca85b94faf7da36` |
| FS `upstream-tools-list.json` | `d9df6889798a48dee9ad78b557dfd638eb618ec580adbd75923af0f64e48f954` |
| Git `upstream-tools-list.json` | `8819c85d38867065dd429515e612f25300811a304e8f9235a46bed943e02ff9b` |

The baselines were selected from the current drivers: `scripts/verify-sou62-real-mcp.py` uses the
frozen classifier for the filesystem profile, and `scripts/verify-sou68-real-mcp.py` uses
`git_readonly_v1` for the Git profile.

On a Windows checkout with `core.autocrlf=true`, `git_readonly_v1/rule_baseline.py` and
`eval_runner.py` are CRLF in the working tree, so they hash differently there. These runs therefore
used the committed blobs, exported with `git show :<path>` (no conversion), and each run's
`results.json` `meta` records the hashes of the bytes that actually executed.

## Matrix (v0.1)

127 cases: 68 benign (66 admitted by the selected profile, plus 2 classifier-only encoding variants)
and 59 adverse, ambiguous or error. Of all cases, 113 are scored and 14 are pending. Six admitted
benign cases exceed the classifier's 200-leaf inspection bound but stay within the profile's 256-item
array bound (`bound_class: above_classifier_leaf_bound`). They are legitimate supported calls.

## Results: selected baseline per profile (`profile_view.json`)

| Profile | Baseline | Scored pass | Fail | Technical | Unscored | Risky misses | Admitted-benign false interruptions |
|---|---|---|---|---|---|---|---|
| filesystem | frozen `d2d43d6f…` | 51/73 | 22 | 0 | 10 | PMF-U05 (`move_file` misses `delete`) | 12/46: `directory_tree` ×8 (PMF-B27…B34), leaf bound ×4 (PMF-B18, B19, B41, B42) |
| git | git_readonly_v1 `8a57c58d…` | 27/40 | 13 | 0 | 4 | PMG-U03 (`git_reset`), PMG-U04 (`git_checkout`): `unknown`, write not predicted | 0/20 |

"Risky" means write, delete, send_data or change_permissions; `write` counts as risky here, unlike
eval_runner's `critical`. A "false interruption" is an admitted benign case predicted `unknown` or with
any risky action. The expected D06 technical failures are not met: PMF-V01, V02, V03 and PMG-V01 are
masked as classifications, the same behaviour as v0.5 E01/E02 for these baselines. All failing IDs
are listed in `profile_view.json`.

Whole matrix under each baseline, for reference: frozen 62/113 and git_readonly_v1 78/113. In both
runs, eval_runner's `critical` misses = 1 (PMF-U05) and constraint violations = 0. Per-case outcomes
are in `<baseline>/matrix/results.{json,csv}`.

## Results: existing public fixtures (unchanged)

| Fixture | frozen | git_readonly_v1 |
|---|---|---|
| v0.4 | 21/21 (2 unscored) | 21/21 (2 unscored) |
| v0.5 | 23/26 | 23/26 |
| challenge v0.2 | 29/35, critical CU02 | 29/35, critical CU02 |
| mixed v0.1 + benign v0.1 | 5/5 | 5/5 |

## Reproduce

```sh
X=$(mktemp -d)   # outside the repository
for p in eval/eval_runner.py rule_baseline/rule_baseline.py rule_baseline/git_readonly_v1/rule_baseline.py \
         eval/fixtures/soup_pilot_readonly_matrix_v0.1.json eval/fixtures/soup_task1_evaluation_cases_v0.4.json \
         eval/fixtures/soup_task1_evaluation_cases_v0.5.json eval/fixtures/soup_task1_challenge_cases_v0.2.json \
         eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json; do
  mkdir -p "$X/$(dirname "$p")"; git show "HEAD:$p" > "$X/$p"
done
cd "$X"
for c in frozen:rule_baseline git_readonly_v1:rule_baseline/git_readonly_v1; do
  n=${c%%:*}; d=${c#*:}; O=$X/out/$n
  python3 -B eval/eval_runner.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json --classifier-path $d --out-dir $O/matrix
  python3 -B eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.4.json --classifier-path $d --out-dir $O/public_v0.4
  python3 -B eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.5.json --classifier-path $d --out-dir $O/public_v0.5
  python3 -B eval/eval_runner.py eval/fixtures/soup_task1_challenge_cases_v0.2.json --classifier-path $d --out-dir $O/public_challenge_v0.2
  python3 -B eval/eval_runner.py eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json \
    eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json --classifier-path $d --out-dir $O/public_mixed_benign
done
python3 -I -B <repo>/eval/evidence/sou97/baseline/profile_view.py eval/fixtures/soup_pilot_readonly_matrix_v0.1.json \
  out/frozen/matrix/results.json out/git_readonly_v1/matrix/results.json
```

The matrix and public-fixture runs exit 1 wherever there are failures (eval_runner exit-code
contract). That is expected for these baselines. `profile_view.py` only reads eval_runner output; a
later increment replaces it with the additive `--pilot-report` mode in `eval/eval_runner.py`.
