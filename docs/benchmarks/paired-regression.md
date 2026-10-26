# Paired development regression (SOU-153)

> **Status: checkpoint, not complete.** Implemented: the input contract, comparability, per-case
> input binding, completeness, paired transitions, missing-outcome bounds, declared unknown
> outcomes, descriptive latency, CSV/Markdown output, controls and a reproducible
> [evidence bundle](evidence/sou153/README.md). Pending: family-aware uncertainty; see
> [remaining work](#remaining-work).
> Phase 4 stays open.

[`paired_regression.py`](../../scripts/benchmarks/paired_regression.py) compares two
recorded runs of the [matched AgentDojo protocol](agentdojo-matched-protocol.md) offline.
It shows whether a candidate revision changes useful behaviour or only moves failures
between categories. It reads JSON only. It sends no model or provider request, runs no
evaluator and leaves the producer unchanged.

Its results are development comparisons. They are not held-out efficacy, general safety
or pilot readiness evidence. Input checks establish that the **supplied inputs** are
identical and consistent, not that the producer executed them.

## Command

```powershell
python scripts/benchmarks/paired_regression.py `
  --baseline-plan P0.json --baseline-run R0.json `
  --candidate-plan P1.json --candidate-run R1.json `
  --inputs SOURCE.json [--families FAMILIES.json] `
  [--baseline-unknowns U0.json] [--candidate-unknowns U1.json] `
  --out-dir <new-or-empty-directory>
```

The command writes these files and prints a one-line status:

- `comparison.json` (`soup-wall-paired-regression/1`);
- `report.md`;
- `units.csv`, for comparable results only.

| Exit | Meaning |
|---|---|
| 0 | Comparison written: `verified_comparable` or `conditionally_comparable`. A regression or partial coverage still exits 0, because this is not a gate. |
| 1 | Valid inputs that are not comparable; no outcomes |
| 2 | Invalid or rejected inputs; no outcomes |
| 3 | Usage error, for example a non-empty output directory |

To reproduce every control, or to check the committed
[checkpoint evidence bundle](evidence/sou153/README.md) byte for byte:

```powershell
python scripts/benchmarks/paired_regression_controls.py --out-dir <new-directory>
python scripts/benchmarks/paired_regression_controls.py --check-evidence
python -m unittest discover -s scripts/benchmarks -p 'test_paired_regression.py' -v
```

## Input contract

| Input | Format | Required |
|---|---|---|
| `--*-plan` | Frozen matched plan, plan schema 2, `soup-wall-agentdojo-matched/1` | yes, one per side |
| `--*-run` | Run report, run schema 2, produced against that plan (`plan_sha256`) | yes, one per side |
| `--inputs` | `soup-wall-paired-regression-inputs/1` source bundle | needed for any comparable result |
| `--families` | `soup-wall-paired-regression-families/1`, separately declared families | only without a case manifest |
| `--*-unknowns` | `soup-wall-paired-regression-unknowns/1`, declared unknown outcomes for that run | optional |

Each side must pass the unchanged `validate_plan` and `validate_run`. A plan freezes one
candidate identity, so each revision needs its own plan. Only the candidate identity
(`identities.candidate`, `identities.policy_sha256`) and the run-level source pins may
differ between sides. They are shown as revision pins.

### Input validity (exit 2)

The comparator applies these checks in order, before any outcome is computed:

1. **File size.** A file larger than `max_file_bytes` (8 MiB) is refused by its size, and
   at most that many bytes are ever read.
2. **Strict JSON.** Duplicate fields, `NaN`/`Infinity`, invalid UTF-8 and runaway nesting
   are refused (`malformed_json`).
3. **Producer contract.** The plan and run schema and protocol must match
   (`incompatible_producer_contract`).
4. **Record counts.** Plan cases, planned units (cases × repetitions), run rows and bundle
   records are bounded before validation (`too_many_records`).
5. **Duplicate case IDs** (`duplicate_case_id`).
6. **Plan binding.** `run.plan_sha256` must equal the SHA-256 of the supplied plan bytes
   (`plan_hash_mismatch`).
7. **Producer validators.** Identity drift, row order, missing or duplicate pair rows,
   Boolean evaluator outputs and budget usage (`plan_contract_violation`,
   `run_contract_violation`).
8. **Optional files.** Malformed bundles, families or unknown annotations
   (`invalid_inputs_bundle`, `invalid_families`, `invalid_unknowns`). An unknown annotation
   bound to another run, or naming a stopped or unrun trajectory, is rejected
   (`unknowns_binding_failed`).

### Comparability

`comparison.json` keeps execution status, input validity, comparability (with `reasons`
and `gaps`), completeness and outcomes as separate fields.

| Status | Meaning |
|---|---|
| `non_comparable` | A check below failed; no outcomes |
| `conditionally_comparable` | All checks passed; outcomes are qualified by the listed gaps |
| `verified_comparable` | All checks passed and every input link, including per-case input, label and family, is verified |

| Reason | Condition |
|---|---|
| `plan_set_mismatch` | Different plan sets, for example development vs fresh evaluation |
| `upstream_mismatch`, `attack_mismatch` | Different upstream revision, suite, version, source inventory or attack |
| `model_identity_mismatch`, `runtime_identity_mismatch` | Different model or runtime identity in the plans |
| `run_settings_unavailable` | A side did not record `settings`, `selection`, `budget`, `model`, `provider`, `provider_url_sha256`, `python_version`, `dependency_lock_sha256` or `dependency_versions` |
| `run_settings_mismatch` | Any of those differs, for example formatter, Ask handling, retries or HTTP timeout |
| `repetitions_mismatch` | Different repetition count |
| `case_missing_in_candidate`, `case_added_in_candidate` | Different case ID sets |
| `case_changed` | Same case ID with a different user task, injection task, vectors, injection hash or expected label |
| `input_identity_unverified` | No `--inputs`; the identities are plan declarations only |
| `input_binding_failed` | A checked input link does not hold |
| `semantic_families_mismatch`, `semantic_families_ambiguous` | `--families` does not cover each case exactly once, or is combined with a case manifest |

| Gap | Condition |
|---|---|
| `case_semantic_input_unverified` | The bundle designates no case manifest |
| `semantic_families_unavailable` | No case manifest and no `--families` |
| `semantic_families_unbound` | Families come from `--families`, not from the inventoried source |
| `unknown_outcomes_declared_overlay` | An unknown annotation was applied |

Two equal declarations are never a verified match. Synthetic provenance is reported in
`input_provenance`. On its own it does not block a comparison whose inputs are verified
identical.

### Input binding

Each link has its own status in `comparability.input_binding.links`:

| Link | Check |
|---|---|
| `run_to_plan` | Each run's `plan_sha256` equals the SHA-256 of its supplied plan bytes |
| `source_to_inventory` | The bundle's `src/` bytes reproduce `source_inventory_sha256` as recorded in the plan **and by the run**. The composition matches the producer's `verify_checkout` (per-file SHA-256 keyed by ASCII path in Git index order, the producer's `encoded`); a test compares it with `verify_checkout` on a real Git checkout. |
| `injections_to_plan` | The injection strings of every attacked case reproduce its `injections_sha256` and vectors; benign cases have none |
| `case_semantic_input` | A case manifest inside the inventoried source agrees with the plan for every compared case, and the per-case full-input hash is identical for both sides |

**Case manifest.** The bundle field `case_manifest` names one of its `src/` files with
schema `soup-wall-paired-regression-cases/1`: `{"schema", "suite", "cases": [...]}`. Each
record has exactly these fields:

- `case_id`, `user_task_id` and `injection_task_id`, which must equal the plan's;
- `expected_label`, which must be `benign` exactly when the plan has no injection task;
- a non-empty `semantic_family`;
- `user_task_file` and `environment_file`, which must be bundled `src/` files.

The manifest is an inventoried file. Its bytes, and so every label and family, are
covered by the inventory hash the run recorded. Changing one on either side changes that
side's inventory and makes the comparison non-comparable.

The comparator derives each case's `case_input_sha256` from these parts:

- the upstream identity and the attack;
- the case and task IDs and the expected label;
- the SHA-256 of the task and environment bytes;
- the injection hash and vectors.

Expected labels still come from the plan; the manifest can only confirm them.

**What remains trusted.** The run's inventory hash is the producer's own runtime record.
The comparator verifies input identity, not execution. Genuine upstream AgentDojo ships no
case manifest, so its case link stays unverified.

**Public examples.** The SOU-36 controlled run has no source bundle, and its neutral task is
defined in test code outside any inventoried source. Both public examples are negative
controls:

- the identity/no-change self-comparison;
- development vs fresh evaluation, which also reports `plan_set_mismatch` and
  `run_settings_mismatch`.

## Completeness and outcomes

A unit is one planned `(case_id, repetition)`. The outcome is the enforced trajectory, with
evaluator outcomes as recorded, including after a Deny or Ask.

| Denominator | Definition |
|---|---|
| planned | Case × repetition units in the frozen plan set |
| attempted | Units whose execution started: evaluable, unknown, or the unit where the run stopped |
| evaluable | Units with an enforced trajectory and recorded evaluator outcomes |
| unknown | Recorded enforced trajectories that a bound annotation declares unknown |
| incomplete | The unit where the run stopped; its evaluators were never reported |
| not_run | Planned units never started |
| paired_evaluable | Units evaluable in both runs; also `evaluable_baseline_only`, `evaluable_candidate_only` and `evaluable_neither` |

| Metric | Value true means | Better |
|---|---|---|
| `security` (`missed_attack_rate`) | The injection evaluator reported attack success | lower |
| `utility` (`benign_utility_rate`) | The benign user task succeeded | higher |
| `utility_under_attack` | The user task succeeded under attack | higher |
| `benign_interruption` | Any Deny or Ask on a benign trajectory | lower |

For each metric the report gives:

- the denominators (planned, evaluable per side, paired-evaluable);
- the transitions on paired-evaluable units;
- the rate on each side's evaluable units;
- missing-outcome bounds;
- the conditional difference;
- an `overall_change` statement.

**Missing-outcome bounds.** Each side's rate is computed on the fixed planned set of P
units, with every missing outcome set to 0 and then to 1: `[k/P, (k + P − evaluable)/P]`.
The difference bounds pair opposite extremes:
`[candidate_low − baseline_high, candidate_high − baseline_low]`. These are bounds for
missing data, not confidence intervals.

**Conditional difference.** `paired_conditional` describes the complete-case intersection,
a different subset from the planned set.

**Overall change.** `overall_change` is always `not_established` in this checkpoint:

- when the bounds include zero, because of the missing outcomes;
- otherwise, because no uncertainty is computed.

No readiness verdict is given, and the plan's acceptance limits are not evaluated.

Worked example (`incomplete_hard_cases_dropped`, security):

- Planned set: 24 attacked units. The baseline evaluates 24 (12 missed attacks). The
  candidate evaluates 8 (0 missed).
- Bounds: [0.5, 0.5] for the baseline and [0, 16/24] for the candidate.
- Difference bounds: [−0.5, +0.167], which include zero.
- The conditional difference on the 8 paired units is −1.0. The overall change is not
  established.

Focused tests check these numbers for all four metrics. Another test makes both sides
incomplete; there, pairing like extremes would wrongly exclude zero.

**Policy decisions and failures:**

- **Policy decisions.** `policy_decisions` counts observed Deny and Ask on every recorded
  enforced trajectory, including unknown ones. Ask is a policy decision and is never
  relabelled as unknown.
- **Failures.** Each stopped unit keeps the producer's `reason` and `error_type` verbatim.
  Timeouts are `count: null` (`undistinguished`), because the producer wraps transport
  timeouts as `AdapterError` with reason `provider_failure`. No censoring duration is
  invented.
- **`undefended_arm_drift`.** Lists units whose undefended outcome differs between runs.

### Unknown outcomes

matched/1 rows carry Boolean evaluator outputs only. Without an annotation, `unknown` is
`unavailable`.

A `soup-wall-paired-regression-unknowns/1` annotation has the fields `schema`,
`run_report_sha256`, `provenance` (`kind`, `assigned_by`, `basis`) and `trajectories`
(`case_id`, `repetition`, `reason`). It binds to one run report by SHA-256 and may name
only recorded enforced trajectories.

For each named unit:

- the recorded evaluator Booleans are withheld;
- the unit counts as attempted and `unknown`, not evaluable;
- the missing-outcome bounds treat it as missing, so it is never a success or a prevented
  attack.

The overlay is always listed as a gap, because the producer did not report it.

## Latency

`latency` describes the enforced trajectories' producer-recorded `task_elapsed_ms` (task) and
`elapsed_ms` (end to end).

**Per side.** For each side and for all, attacked and benign units, the report gives
`n`, `min`, `median`, `p95` and `max`, computed with `agentdojo_protocol.distribution`:

- the median is the middle value, or the mean of the two middle values when `n` is even;
- `p95` is the nearest rank, the value at rank ⌈0.95 · n⌉ of the sorted sample.

**Measurement versus outcome.** A recorded enforced trajectory carries its durations
whether its evaluator outcome is known (`measured_with_evaluator_outcome`) or declared
unknown (`measured_with_unknown_outcome`). An unknown outcome does not invalidate the
recorded time.

**Missing durations.** Stopped units (`stopped_duration_unavailable`) and `not_run` units
have no duration:

- the producer records none for a stopped attempt;
- they are counted, never imputed or set to zero, and never presented as measured
  censored durations;
- timeouts stay `count: null` (`undistinguished`).

**Paired.** Only for a comparable result: `candidate − baseline` distributions over the
matched verified units measured on both sides. `paired_measured` is this latency
denominator. It can differ from `paired_evaluable`, for example when outcomes are unknown.
The fields `measured_baseline_only`, `measured_candidate_only` and `coverage_differs` show
coverage changes.

**No speed claim.** `change` is always `not_stated`: no uncertainty is computed, and when
coverage differs, the per-side distributions describe different unit sets. Latency is not
a gate.

## Grouping

- **Dependency clusters.** Connected components of cases that share a `user_task_id`, an
  `injection_task_id` or a non-empty `injections_sha256`. They record known statistical
  dependencies and are not semantic families. The committed workspace plan shares seven
  injection tasks among eight development user tasks.
- **Semantic families.** These come from the verified case manifest
  (`bound_by_source_inventory`) or from `--families` (`declared_unbound`, listed as a gap).
  Families never carry or change expected labels.
- **Resampling units.** Dependency clusters merged with families. They will be the unit of
  the family-aware uncertainty. A dataset that collapses into one unit will report
  insufficient samples rather than split correlated cases.

## Controls

[`paired_regression_controls.py`](../../scripts/benchmarks/paired_regression_controls.py)
generates synthetic inputs from fixed values:

- 12 invented user tasks, 2 repetitions and six invented themes as families;
- a synthetic source with one prompt file per task, an environment and a case manifest.

Every generated plan and run passes the producer validators. Inputs and outcomes are
generated to test the comparator's accounting, and the provenance says so.

| Control | Expected |
|---|---|
| improved, regressed, no_change | exit 0, `verified_comparable`, exact transitions |
| incomplete_hard_cases_dropped | `verified_comparable`, partial; conditional −1.0 while bounds include zero |
| all_unevaluable | `verified_comparable`, zero paired-evaluable units, all rates null |
| manifest_not_designated | `conditionally_comparable`; gaps `case_semantic_input_unverified`, `semantic_families_unbound` |
| all_unknown | `conditionally_comparable`; every candidate outcome unknown, 0 evaluable, bounds [0, 1] |
| missing_case, changed_input, substituted_task_input, settings_mismatch, unverified_inputs | exit 1 with the matching reasons |
| unknowns_wrong_run, tampered_plan, tampered_row, duplicate_case_id, incompatible_contract, non_finite | exit 2 with the matching codes |
| public_identity_no_change, public_dev_vs_fresh | exit 1, `input_identity_unverified` (negative controls) |

The tests also substitute a task prompt, an expected label or a family on one side, and
consistently on both sides.

## Remaining work

- **Uncertainty.** Family-aware uncertainty over resampling units (planned: paired cluster
  bootstrap with a fixed seed), with its estimand, data-checked weights, an explicitly
  justified sufficiency rule and its limitations.
- **Public data.** No public run has a source bundle or case manifest, so no public
  comparison is verified and no public semantic families are declared.
- **Unknown outcomes.** These rely on the declared annotation contract. No existing
  producer emits it.
