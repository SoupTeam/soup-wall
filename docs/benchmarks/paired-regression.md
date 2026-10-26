# Paired development regression (SOU-153)

> **Status: checkpoint, not complete.** Input contract, comparability, completeness,
> paired transitions and synthetic controls are implemented. Family-aware uncertainty,
> latency distributions, the CSV/Markdown outputs and the evidence bundle are pending;
> see [not yet implemented](#not-yet-implemented). Phase 4 stays open.

[`paired_regression.py`](../../scripts/benchmarks/paired_regression.py) compares two
recorded runs of the [matched AgentDojo protocol](agentdojo-matched-protocol.md) offline.
It shows whether a candidate revision changes useful behaviour or only moves failures
between categories. It reads JSON only. It sends no model or provider request, runs no
evaluator and leaves the producer unchanged. It reports development comparisons; they are
not held-out efficacy, general safety or pilot readiness evidence.

## Command

```powershell
python scripts/benchmarks/paired_regression.py `
  --baseline-plan P0.json --baseline-run R0.json `
  --candidate-plan P1.json --candidate-run R1.json `
  [--inputs SOURCE.json] [--families FAMILIES.json] --out-dir <new-or-empty-directory>
```

The command writes `comparison.json` (schema `soup-wall-paired-regression/1`) and prints a
one-line status.

| Exit | Meaning |
|---|---|
| 0 | Comparison report written. A regression or partial coverage still exits 0, because this is not a gate. Check `comparability.status` and `gaps`. |
| 1 | Valid inputs that are not comparable; no outcomes are reported |
| 2 | Invalid or rejected inputs; no outcomes are reported |
| 3 | Usage error, for example a non-empty output directory |

Run the synthetic and public controls with one command:

```powershell
python scripts/benchmarks/paired_regression_controls.py --out-dir <new-directory>
python -m unittest discover -s scripts/benchmarks -p 'test_paired_regression.py' -v
```

## Input contract

| Input | Producer / format | Required |
|---|---|---|
| `--*-plan` | Frozen matched plan, plan schema 2, `soup-wall-agentdojo-matched/1` | yes, one per side |
| `--*-run` | Run report, run schema 2, produced against that plan (`plan_sha256`) | yes, one per side |
| `--inputs` | `soup-wall-paired-regression-inputs/1` source bundle | needed for a comparable result |
| `--families` | `soup-wall-paired-regression-families/1` declared semantic families | optional |

Each side must pass the unchanged `validate_plan` and `validate_run`. Both revisions
therefore need their own plan, because a plan freezes one candidate identity. Only the
candidate identity (`identities.candidate`, `identities.policy_sha256`) and the run-level
source pins may differ between sides; they are shown as revision pins.

### Input validity (exit 2)

The comparator applies these checks in order, before any outcome is computed:

1. **File size.** A file larger than `max_file_bytes` (8 MiB) is refused by its size, and
   at most that many bytes are ever read.
2. **Strict JSON.** Duplicate fields, `NaN`/`Infinity`, invalid UTF-8 and runaway nesting
   are refused (`malformed_json`).
3. **Producer contract.** The plan and run schema and protocol must match
   (`incompatible_producer_contract`).
4. **Record counts.** Plan cases, planned units (cases × repetitions) and run rows are
   bounded before validation (`too_many_records`).
5. **Duplicate case IDs** (`duplicate_case_id`).
6. **Plan binding.** `run.plan_sha256` must equal the SHA-256 of the supplied plan bytes
   (`plan_hash_mismatch`).
7. **Producer validators.** Identity drift, row order, missing or duplicate pair rows,
   Boolean evaluator outputs and budget usage (`plan_contract_violation`,
   `run_contract_violation`).

### Comparability (exit 1)

| Code | Condition |
|---|---|
| `plan_set_mismatch` | Different plan sets (for example development vs fresh evaluation) |
| `upstream_mismatch`, `attack_mismatch` | Different upstream revision, suite, version, inventory or attack |
| `model_identity_mismatch`, `runtime_identity_mismatch` | Different model or runtime identity in the plans |
| `run_settings_unavailable` | A side did not record `settings`, `selection`, `budget`, `model`, `provider`, `provider_url_sha256`, `python_version`, `dependency_lock_sha256` or `dependency_versions` |
| `run_settings_mismatch` | Any of those differs, for example formatter, Ask handling, retries or HTTP timeout |
| `repetitions_mismatch` | Different repetition count |
| `case_missing_in_candidate`, `case_added_in_candidate` | Different case ID sets |
| `case_changed` | Same case ID with a different user task, injection task, vectors, injection hash or expected label |
| `input_identity_unverified` | No `--inputs`: the identities are plan declarations only |
| `input_binding_failed` | The supplied source bytes do not reproduce the declared identities |
| `semantic_families_mismatch` | Families do not cover each compared case exactly once |

Two equal declarations are not a verified match. Without a source bundle a comparison is
always non-comparable.

When every check passes, the result is still qualified by its `gaps`:

| Status | Meaning |
|---|---|
| `non_comparable` | A check failed; no outcomes (exit 1 or 2) |
| `conditionally_comparable` | All checks passed; outcomes are diagnostics qualified by the listed gaps (exit 0) |
| `verified_comparable` | No gaps. Unreachable for matched/1 until per-case semantic input binding exists. |

| Gap | Condition |
|---|---|
| `case_semantic_input_unverified` | Always listed today; see below |
| `semantic_families_unavailable` | No `--families` |
| `synthetic_inputs` | The source bundle declares synthetic provenance |

### Input identity binding

The plan names cases by `user_task_id` and `injection_task_id`. It also records
`injections_sha256` (the SHA-256 of the canonical injection strings) and the upstream
`source_inventory_sha256`. The run records the inventory hash that the producer computed
from the checkout it loaded. User task and environment content is covered only by that
whole-source inventory hash. Run settings are not in the plan.

Each link has its own status in `comparability.input_binding.links`:

| Link | Check | Status |
|---|---|---|
| `run_to_plan` | Each run's `plan_sha256` equals the SHA-256 of its supplied plan bytes | verified, or the input is rejected |
| `source_to_inventory` | The bundle's `src/` bytes reproduce the plan's and the run's recorded `source_inventory_sha256` | verified / mismatch / not_supplied |
| `injections_to_plan` | The injection strings of every attacked case reproduce its `injections_sha256` and vectors; benign cases have none | verified / mismatch / not_supplied |
| `case_semantic_input` | That a case's full user task and environment content belong to that case ID | **unverified** |

The inventory hash uses the producer's `verify_checkout` composition: the SHA-256 of each
file's exact bytes, keyed by ASCII path in Git index order and serialized with the
producer's `encoded`. A test checks the result against `verify_checkout` on a real Git
checkout.

No producer record binds a case ID to the content it resolves to; the inventory hash
covers the source only as a whole. A matching string in the source is not treated as that
binding. The overall binding status is therefore at most `partially_verified`. The run's
inventory hash also remains the producer's own runtime record.

**Synthetic controls.** Their inputs and outcomes are generated by
`paired_regression_controls.py` to test the comparator's accounting. They are not
evidence of any historical execution, and the `synthetic_inputs` gap says so.

**Public examples.** No source bundle exists for the SOU-36 controlled run, and its neutral
task is defined in test code outside any inventoried source. Both public examples end as
`non_comparable`:

- the self-comparison (identity/no-change control);
- the development-vs-fresh comparison (negative comparability control), which also reports
  `plan_set_mismatch` and `run_settings_mismatch`.

## Completeness and outcomes

A unit is one planned `(case_id, repetition)`. The outcome is the enforced trajectory, with
evaluator outcomes as recorded, including after a Deny or Ask.

| Denominator | Definition |
|---|---|
| planned | Case × repetition units in the frozen plan set |
| attempted | Units whose execution started: evaluable, or the unit where the run stopped |
| evaluable | Units with an enforced trajectory and recorded evaluator outcomes |
| incomplete | The unit where the run stopped; its evaluators were never reported |
| not_run | Planned units never started |
| paired_evaluable | Units evaluable in both runs; also `evaluable_baseline_only`, `evaluable_candidate_only`, `evaluable_neither` |

`comparison.json` keeps execution status, input validity, comparability and completeness
as separate fields. Outcomes exist only for a comparable result:

| Metric | Value true means | Better |
|---|---|---|
| `security` (`missed_attack_rate`) | The injection evaluator reported attack success | lower |
| `utility` (`benign_utility_rate`) | The benign user task succeeded | higher |
| `utility_under_attack` | The user task succeeded under attack | higher |
| `benign_interruption` | Any Deny or Ask on a benign trajectory | lower |

For each metric the report gives:

- `denominators`: planned, evaluable per side and paired-evaluable;
- the transitions (improved, regressed, unchanged) on paired-evaluable units;
- the rate on each side's own evaluable units;
- missing-outcome bounds, described below;
- the `paired_conditional` difference on the complete-case intersection;
- an `overall_change` statement.

**Missing-outcome bounds.** Each side's rate is computed on the fixed planned set of P
units, with every missing outcome set to 0 and then to 1: `[k/P, (k + P - evaluable)/P]`.
The difference bounds pair opposite extremes:
`[candidate_low - baseline_high, candidate_high - baseline_low]`. These are bounds for
missing data, not a confidence interval.

**Conditional difference.** `paired_conditional` describes a different subset, the units
evaluable in both runs. It is not comparable with the planned-set bounds.

**Overall change.** `overall_change` is always `not_established` in this checkpoint. When
the bounds include zero, the reason is `missing-outcome bounds include zero`. Otherwise the
reason is that no uncertainty is computed. Missing or stopped work never counts as a
prevented attack or a success. No overall direction or readiness verdict is stated, and
the plan's acceptance limits are not evaluated.

Worked example (`incomplete_hard_cases_dropped`, security):

- Planned set: 24 attacked units. The baseline evaluates 24 (12 missed attacks). The
  candidate evaluates 8 (0 missed).
- Baseline bounds: [12/24, 12/24].
- Candidate bounds: [0/24, (0 + 16)/24] = [0, 0.667].
- Difference bounds: [0 − 0.5, 0.667 − 0.5] = [−0.5, +0.167], which include zero.
- The conditional difference on the 8 paired units is −1.0. The overall change is not
  established.

A focused test checks these numbers for all four metrics. A second test makes both sides
incomplete; there, pairing like extremes would wrongly exclude zero.

Other fields:

- **`policy_decisions`.** Observed Deny and Ask counts per side. Ask is an observed
  decision, not an unknown outcome.
- **`unknown`.** Always `unavailable`: matched/1 rows carry Boolean evaluator outputs only.
- **Failures.** Each stopped unit keeps the producer's `reason` and `error_type` verbatim.
  Timeouts are `count: null` (`undistinguished`), because the producer wraps transport
  timeouts as `AdapterError` with reason `provider_failure`. No censoring duration is
  invented.
- **`undefended_arm_drift`.** Lists units whose undefended outcome differs between runs.
  Such a difference points to harness, provider or environment drift, since the
  undefended arm should not depend on the candidate revision.

## Grouping

- **Dependency clusters** are connected components of cases that share a `user_task_id`,
  an `injection_task_id` or a non-empty `injections_sha256`. They record known statistical
  dependencies. They are not semantic families. The committed workspace plan shares seven
  injection tasks among eight development user tasks.
- **Semantic families** are unavailable unless `--families` declares them. The file
  records provenance (`kind`, `assigned_by`, `basis`) and lists case IDs only. It cannot
  carry or change expected labels, which always come from the plan. Every compared case
  must be in exactly one family. The synthetic controls declare six invented themes.
- **Resampling units** merge dependency clusters with declared families. They will be the
  unit of the family-aware uncertainty. A dataset that collapses into one unit will report
  insufficient samples rather than split correlated cases.

## Synthetic controls

[`paired_regression_controls.py`](../../scripts/benchmarks/paired_regression_controls.py)
generates synthetic inputs from fixed values: 12 invented user tasks, 2 repetitions, and
an invented source bundle and family file, all marked `synthetic`. Every generated plan
and run passes the producer validators.

| Control | Expected |
|---|---|
| improved, regressed, no_change | exit 0, `conditionally_comparable` (gaps: `case_semantic_input_unverified`, `synthetic_inputs`), exact transitions |
| incomplete_hard_cases_dropped | as above, partial; conditional difference −1.0 while missing-outcome bounds include zero |
| all_unevaluable | as above, zero paired-evaluable units, all rates null |
| missing_case, changed_input, settings_mismatch, unverified_inputs | exit 1 with the matching codes |
| tampered_plan, tampered_row, duplicate_case_id, incompatible_contract, non_finite | exit 2 with the matching codes |
| public_identity_no_change, public_dev_vs_fresh | exit 1, `input_identity_unverified` |

## Not yet implemented

- **Uncertainty.** Family-aware uncertainty (planned: paired cluster bootstrap over
  resampling units with a fixed seed). The estimand, weights, sufficiency rule and
  limitations are to be documented with it.
- **Latency.** Latency distributions and paired latency differences next to stopped and
  not-run counts.
- **Outputs and evidence.** `units.csv`, a readable report and a committed evidence
  bundle with a byte-for-byte reproduction check.
- **Open acceptance gap: unknown outcomes.** The matched/1 producer cannot report an
  unknown outcome, so this comparator has no genuine all-unknown control. An Ask is not
  relabelled as unknown.
- **Open acceptance gap: per-case semantic input binding.** No `verified_comparable`
  result is possible yet. Genuine upstream runs have no source bundle path; their
  injection and selection binding currently needs the producer's `--mode plan-check`
  against the pinned checkout.
- **Semantic families for public data** are not declared.
