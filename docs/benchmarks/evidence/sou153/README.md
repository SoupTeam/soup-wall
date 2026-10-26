# SOU-153 evidence

Offline evidence for the [paired development regression comparator](../../paired-regression.md),
including its [family-aware uncertainty](../../paired-regression.md#family-aware-uncertainty).
No model, provider, evaluator, upstream checkout or private data was used. Open review
questions are listed under [remaining](#remaining).

## Reproduce

From the repository root, with Python 3.10+ (standard library only):

```powershell
python scripts/benchmarks/paired_regression_controls.py --check-evidence
```

The command regenerates every generated file into a temporary directory. It compares them
byte for byte with this directory (everything except this README) and exits 1 on any
difference. `SHA256SUMS` lists the generated files. Outputs record input file names, never
absolute paths. The only timestamps are the fixed synthetic plan and run times.
`.gitattributes` keeps these files LF on every platform, because inputs are bound by
raw-byte SHA-256.

To rebuild the directory, delete it and run `--write-evidence docs/benchmarks/evidence/sou153`.

| Path | Content |
|---|---|
| `inputs/inputs.json` | Synthetic source bundle: `src/` files, including the case manifest and the injection strings |
| `inputs/baseline-*.json`, `inputs/candidate-plan.json` | Shared synthetic matched/1 plans and baseline run |
| `inputs/<control>/` | Candidate inputs specific to one control; identical inputs are stored once (`all_unknown` reuses the `improved` run) |
| `inputs/improved_fine_families/` | The 12-family synthetic world: its own source bundle, baseline plan and run, and candidate plan; `regressed_fine_families` reuses them |
| `results/<control>/` | `comparison.json`, `report.md` and, for comparable results, `units.csv` |

## Results

All synthetic controls compare 12 invented user tasks × (benign + attacked) × 2 repetitions:
48 planned units, 24 attacked and 24 benign.

| Control | Comparability | Completeness | Key numbers (candidate − baseline) |
|---|---|---|---|
| `improved` | verified_comparable | complete | Missed attacks 12/24 → 2/24: 10 improved, 0 regressed. Benign utility unchanged (22/24). |
| `regressed` | verified_comparable | complete | Missed attacks 12/24 → 18/24 (6 regressed). Benign utility 22/24 → 18/24 (4 regressed). Benign interruptions 2/24 → 6/24. |
| `improved_fine_families` | verified_comparable | complete | Same outcomes as `improved`, but each user task is its own family (12 resampling units). |
| `regressed_fine_families` | verified_comparable | complete | Same outcomes as `regressed`, with 12 resampling units. |
| `incomplete_hard_cases_dropped` | verified_comparable | partial | 18 of 48 units paired. Conditional missed-attack difference −1.0 on 8 paired attacked units, but missing-outcome bounds [−0.5, +0.167] include zero. Overall change not established. |
| `all_unevaluable` | verified_comparable | partial | Zero-denominator control: the candidate stopped on its first trajectory (`provider_failure`); 0 paired units, all rates null. |
| `all_unknown` | conditionally_comparable (gap: `unknown_outcomes_declared_overlay`) | partial | 48 candidate units unknown, 0 evaluable, 0 paired. Candidate bounds [0, 1]. No transitions. |
| `missing_case` | non_comparable: `case_missing_in_candidate`, `input_binding_failed`, `run_settings_mismatch` | per side only | The candidate plan omits the last user task. |
| `substituted_task_input` | non_comparable: `upstream_mismatch`, `input_binding_failed` | per side only | The candidate ran against source with a different prompt for one user task. |
| `public_identity_no_change` | non_comparable: `input_identity_unverified` | per side only | Public SOU-36 run compared with itself; no outcomes. |

No readiness verdict is produced, and security and useful-behaviour metrics are never merged.

### Family-aware uncertainty

Pairs cluster bootstrap over resampling units, seed 153, 2000 replicates, 95% percentile
interval, reported only with at least 10 effective clusters. Differences are candidate −
baseline on the paired-evaluable units.

| Control | Resampling units | Missed-attack difference | Benign utility difference | Attacked utility difference | Benign interruption difference |
|---|---|---|---|---|---|
| `improved` | 6 | −0.417, `insufficient_clusters` | 0.0, `insufficient_clusters` | −0.417, `insufficient_clusters` | 0.0, `insufficient_clusters` |
| `regressed` | 6 | +0.25, `insufficient_clusters` | −0.167, `insufficient_clusters` | +0.25, `insufficient_clusters` | +0.167, `insufficient_clusters` |
| `improved_fine_families` | 12 | −0.417 [−0.667, −0.167]: **improved** | 0.0 [0, 0] (degenerate): not established | −0.417 [−0.667, −0.167]: **regressed** | 0.0 [0, 0] (degenerate): not established |
| `regressed_fine_families` | 12 | +0.25 [0, +0.5]: not established | −0.167 [−0.417, 0]: not established | +0.25 [0, +0.5]: not established | +0.167 [0, +0.417]: not established |
| `incomplete_hard_cases_dropped` | 6 | 2–3 informative units: `insufficient_clusters`; bounds include zero | | | |
| `all_unevaluable`, `all_unknown` | 6 | `zero_denominator` for every metric | | | |

What this shows about the comparator:

- **Correlated variants are not counted as independent.** The 6-family controls have 48
  paired units and the same transitions as the 12-family controls, yet report no
  interval.
- **The metrics stay separate.** In `improved_fine_families` the newly denied attacks also
  lose their user task. Security improves while utility under attack regresses, and the
  two are not netted out.
- **The intervals are not tuned to look decisive.** In `regressed_fine_families` three of
  twelve families regress. The lower end of the interval reaches 0, so no regression is
  established.

For `improved_fine_families`, security can be checked by hand. A resample draws K ~
Binomial(12, 5/12) improving families, and the exact 2.5% and 97.5% quantiles of K are
2 and 8, giving [−8/12, −2/12]. A test checks this.

In `all_unknown`, each metric's `unknown_annotation_audit` shows that the annotation
withholds 24 attacked units, on which the producer recorded 10 security improvements.
These are never counted.

## What this evidence shows and does not show

### Verified comparability of the supplied synthetic inputs

For every comparable control except `all_unknown` (which is conditional only because of its
annotation gap), every input link is verified:

- each run is bound to its plan by `plan_sha256`;
- the bundle's `src/` bytes reproduce the inventory hash recorded by both plans and runs,
  with the producer's `verify_checkout` composition;
- the injection strings reproduce the planned injection hashes;
- the inventoried case manifest binds every case ID to its task and environment files,
  expected label and semantic family, with identical per-case input hashes on both sides.

This establishes that the supplied inputs are identical and consistent. It does not
establish that any producer executed them.

### Generated outcomes, not measurements

All synthetic plans, runs, outcomes and families are generated by
`paired_regression_controls.py`, and their provenance says `synthetic`. They test the
comparator's accounting (statuses, denominators, transitions, bounds and intervals). They
do not measure any revision's effectiveness and are not development, held-out or safety
evidence. An "improved" statement here shows that the comparator can establish a change;
it is not evidence that any candidate is effective.

### Public example limits

`public_identity_no_change` reads the existing
[`sou36/controlled`](../sou36/controlled) plan and development run in place, without
copying them.

- No source bundle exists for that run, and its neutral task is defined in test code
  outside any inventoried source.
- Input identity therefore stays `declared_unverified`, and the result is a negative
  control.
- It is a self-comparison (identity/no-change), not a comparison of two revisions.
- No public semantic families are declared.

### Unknown outcomes from an additional annotation

matched/1 reports no unknown outcome. `all_unknown` applies a
`soup-wall-paired-regression-unknowns/1` annotation, which is bound to the candidate run
report by SHA-256 and marks every enforced trajectory unknown.

For those units:

- the recorded evaluator Booleans are withheld;
- the units count as attempted but not evaluable;
- the missing-outcome bounds treat them as missing;
- observed Deny/Ask remain visible as policy decisions.

This annotation contract is a proposal of SOU-153. Its acceptance as the way to
satisfy the unknown requirement has not been confirmed by the task owner, and no existing
producer emits it.

### Missing, stopped and timeout outcomes

- Stopped and not-run units have no evaluator outcome. The CSV leaves their outcome cells
  empty and marks their transitions `not_paired`.
- Timeouts cannot be distinguished in matched/1, so every report shows them as
  `not available (undistinguished)` rather than zero.

### Latency (descriptive)

Each result reports enforced `task_elapsed_ms` and `elapsed_ms` per side (n, min, median,
nearest-rank p95, max). Paired candidate − baseline differences use only units measured on
both sides, and `paired_measured` is their denominator. No speed-up or slow-down is stated
(`change: not_stated`).

| Control | Candidate measured / planned | Stopped (duration unavailable) / not run | Paired measured | Paired task difference median / p95 (ms) |
|---|---|---|---|---|
| `improved` | 48 / 48 | 0 / 0 | 48 | 0 / 10 |
| `regressed` | 48 / 48 | 0 / 0 | 48 | 0 / 30 |
| `incomplete_hard_cases_dropped` | 18 / 48 | 1 / 29 | 18 (coverage differs) | 0 / 10 |
| `all_unknown` | 48 / 48, all with unknown outcome | 0 / 0 | 48 (paired evaluable: 0) | 0 / 10 |

Unknown evaluator outcomes keep their recorded durations. Stopped and not-run units have no
duration and are never imputed or treated as censored measurements. The synthetic
durations are generator constants, not measurements.

## Remaining

- Review of the statistical constants: the minimum of 10 effective clusters, the
  percentile interval and B = 2000.
- A decision on whether the unknown annotation contract satisfies the requirement.
- A public comparison with two revisions, a source bundle and declared families. None
  exists, so no public result is comparable.
