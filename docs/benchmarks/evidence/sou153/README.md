# SOU-153 evidence

Offline evidence for the [paired development regression comparator](../../paired-regression.md),
including its [family-aware uncertainty](../../paired-regression.md#family-aware-uncertainty).
No model, provider, evaluator, upstream checkout or private data was used.

The methodology is approved for **exploratory development diagnostics only**
([DEC-SOU153-20261027](../../paired-regression.md#approved-scope-dec-sou153-20261027)).
Nothing here is held-out efficacy, safety or pilot-readiness evidence. No verified
two-revision public comparison exists; see the
[public report inventory](#public-report-inventory) and [remaining](#remaining).

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
| `public_identity_no_change` | non_comparable: `input_identity_unverified` | per side only | Public SOU-36 scripted-fixture run compared with itself; no outcomes. |
| `public_dev_vs_fresh` | non_comparable: `plan_set_mismatch`, `run_settings_mismatch`, `input_identity_unverified` | per side only | Public SOU-36 scripted-fixture development run vs fresh-evaluation run of the same revision; no outcomes. A labelled negative control, **not** a two-revision comparison. |

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

Both public examples read the existing [`sou36/controlled`](../sou36/controlled) plan and
runs in place, without copying or changing them.

- **They are scripted fixture runs, not live AgentDojo runs.** SOU-36 produced them
  through the production `run_live` path, but with:
  - a scripted loopback model that always makes the same tool call;
  - a neutral suite defined in test code;
  - a test policy (`default: deny`) instead of the shipped policy.

  Their outcomes exercise the protocol and measure no revision's behaviour.
- No source bundle exists for those runs, and their neutral task is defined in test code
  outside any inventoried source.
- Input identity therefore stays `declared_unverified`, and both results are negative
  controls.
- Neither compares two revisions. `public_identity_no_change` is a self-comparison.
  `public_dev_vs_fresh` compares two plan sets of one revision.
- No public semantic families are declared.

`public_dev_vs_fresh` is the exact output of this command, run from the repository root:

```powershell
python scripts/benchmarks/paired_regression.py `
  --baseline-plan docs/benchmarks/evidence/sou36/controlled/plan.json `
  --baseline-run docs/benchmarks/evidence/sou36/controlled/development-run.json `
  --candidate-plan docs/benchmarks/evidence/sou36/controlled/plan.json `
  --candidate-run docs/benchmarks/evidence/sou36/controlled/fresh-run.json `
  --out-dir <new-directory>
```

It exits 1 and prints this line, followed by the path written:

```text
exit 1: comparability=non_comparable validity=valid completeness=per_side_only reasons=[plan_set_mismatch, run_settings_mismatch, input_identity_unverified] gaps=[none]
```

| Reason | Detail |
|---|---|
| `plan_set_mismatch` | baseline `development` vs candidate `fresh_evaluation` |
| `run_settings_mismatch` | differs in `selection.repetitions` and `budget.max_calls` |
| `input_identity_unverified` | no source bundle: task, environment and injection identities are plan declarations |

A test runs this command and checks that the output is byte-identical to the retained
`comparison.json` and `report.md`.

### Public report inventory

These are all public AgentDojo reports in the repository. The search covered every
commit reachable from all 245 remote branches (2026-10-28). The matched/1 protocol
string was only ever added by SOU-36 (`6fe98d71`) and the SOU-153 commits. None of
these reports forms a verified two-revision matched/1 pair, so none could be compared
without fabricating plans, outcomes or input bindings. None was converted.

| Report | Source revision | Format | Usable as a comparison side |
|---|---|---|---|
| [`sou36/controlled`](../sou36/controlled) plan, `development-run.json`, `fresh-run.json` | `neutral-fixture` (base `290e043b`, modified working tree; agent binary `05de4e82…`) | matched/1 plan and run reports (schema 2) from a **scripted fixture run** (loopback model, neutral test suite, test policy); not a live AgentDojo run | Yes, but this is the only revision; used by both public controls |
| [`agentdojo-sou36-workspace.plan.json`](../../../../scripts/benchmarks/agentdojo-sou36-workspace.plan.json) | `290e043b` | matched/1 plan for the real `workspace` suite | No run exists: both live attempts were refused at the live gate ([development](../sou36/workspace-live-blocked-development.json), [fresh](../sou36/workspace-live-blocked-fresh_evaluation.json)) |
| `agentdojo-fallback-after-native-2026-10-05.json`, `agentdojo-fallback-after-review-2026-10-05.json`, `agentdojo-live-fixture-2026-10-05.json`, `agentdojo-native-after-review-2026-10-05.json` | `e259b76b`, `0c333cd8`, `38de3fda`, `0c333cd8` | Schema-1 fixture and native test reports | No: pass/fail checks, no plan and no per-case outcomes |
| [`sou85`](../sou85) report and attempts | `ad41af50` | Schema-1 offline acceptance; attempts incomplete | No |
| `agentdojo-history-2026-10-04.json` | n/a | Historical import summary | No |

No public report has a source bundle, a case manifest or frozen semantic families.

### Two-revision availability assessment

**Strongest candidate pair:**

- **Baseline:** `6fe98d71fc2b806d996ec0ca493f20f4d9da2202` (SOU-36). It is the first commit with the matched/1 producer, and uses the fallback adapter.
- **Candidate:** `ad41af500710450e8f1697da57eafdf5571301fa` (SOU-85). It uses the native adapter with the pinned workspace profile.

These two share the frozen workspace plan, the protocol, the dependency lock and the
shipped policy. Changes that cannot reach the AgentDojo adapters were rejected, such as
#275's MCP-only result-directive detector.

| Requirement | `6fe98d71` (baseline) | `ad41af50` (candidate) | Status |
|---|---|---|---|
| Frozen plan | `agentdojo-sou36-workspace.plan.json`, SHA-256 `42513a67…ad24a`, byte-identical at both commits | same file | Exists, but it freezes **one** candidate identity: source `290e043b`, fallback adapter, `agent_binary_sha256` null, model unset, access `not_selected`/`not_approved`. Neither revision can run against it unchanged: the binary is unfrozen, and the native adapter fails the producer's identity check. A plan per revision would be needed, and none exists. |
| matched/1 run report | none; both live attempts refused at the gate with 0 model calls | none; the SOU-85 report is schema 1, `workspace-offline`, with 185 pass/fail checks, no case IDs and no plan binding | **Missing on both sides.** The comparator cannot be invoked. |
| Upstream source | `089ed468`, inventory `f030c2fc…49a4` | the same inventory in the SOU-85 report | **Verified.** A public clone of `ethz-spylab/agentdojo` at `089ed468` reproduces `f030c2fc…49a4` over 112 `src/` files, with both the producer's `verify_checkout` and the comparator's `source_inventory_sha256`. |
| Cases and expected labels | 16 development cases (8 user tasks; each benign plus attacked) | same plan | Reproduced from upstream at freeze time ([`workspace-plan-check.json`](../sou36/workspace-plan-check.json): `reproduced: true`, no errors). Labels follow the plan. |
| Per-case input, label and family link | none: upstream AgentDojo ships no case manifest | none | **Unverifiable** without changing the upstream source, which would change its inventory. At best `conditionally_comparable`. |
| Semantic families | none | none | **Missing**; no mapping exists in any branch. Not invented. |
| Policy | `8b2bfb66…` | `8b2bfb66…` | Identical shipped bytes. |
| Agent binary / adapter | not frozen; fallback | `31c6a416…` in the SOU-85 report; `sw-native/1`, profile `452cf47a…`, registry `cd8a16f5…` | Differs, as a revision pair should. Shown as pins, not a comparability failure. |

**Statistical ceiling.** On this development set every metric has 8 planned units in 6
dependency clusters of sizes 1, 1, 1, 1, 1 and 3. That is at most 64/14 ≈ 4.57 effective
clusters, below the approved minimum of 10. Families can only merge clusters. Even
complete genuine runs on both revisions would report `insufficient_clusters`, with no
interval and no established change.

**Missing evidence, invalid input and a real `non_comparable` result:**

| Case | Outcome |
|---|---|
| `6fe98d71` → `ad41af50` | **Missing evidence.** No run reports exist, so the comparator has nothing to compare. |
| SOU-36 controlled development run bound to the workspace plan | **Invalid input:** exit 2, `plan_hash_mismatch`. The comparator refuses a run that was not produced against the supplied plan. |
| SOU-36 development vs fresh (`public_dev_vs_fresh`) | **Comparator-produced `non_comparable`** (exit 1), on the SOU-36 scripted-fixture reports of one revision. Retained as a negative control, not a two-revision comparison. |

**To reproduce the upstream inventory check**, clone `https://github.com/ethz-spylab/agentdojo.git`,
check out `089ed468cf3ed0322acc66b0211f26d9d90dbf60`, then run from the repository root:

```powershell
python -I -c "import sys; sys.path.insert(0, 'scripts/benchmarks'); import agentdojo_live as a; from pathlib import Path; print(a.verify_checkout(Path(sys.argv[1]))['source_inventory_sha256'])" <upstream-checkout>
```

It should print `f030c2fce6daf25a5206270f9bcfff789decf4f0421143199003c703f42349a4`.
A test checks the plan, plan-binding, report-format and cluster facts in this section
against the committed files.

### Unknown outcomes from a supplementary annotation

matched/1 reports no unknown outcome. `all_unknown` applies a
`soup-wall-paired-regression-unknowns/1` annotation. It is bound to the candidate run
report by SHA-256 and marks every enforced trajectory unknown. The contract is accepted
as diagnostic censoring by DEC-SOU153-20261027. It is never reported as a producer
outcome, and no existing producer emits it.

For those units:

- the recorded evaluator Booleans are excluded from every outcome, transition, bound and
  interval;
- the units count as attempted but not evaluable, and the CSV outcome cells are empty;
- the missing-outcome bounds treat them as missing;
- each unit keeps the producer-recorded `utility` and `injection_success` under
  `producer_recorded_audit`, for audit only;
- the observed Deny/Ask stay on each unit and in `policy_decisions`;
- the comparison is `conditionally_comparable`, with gap `unknown_outcomes_declared_overlay`.

Only `results/all_unknown/comparison.json` carries the audit field. It was added after
DEC-SOU153-20261027, and removing it leaves the previous file byte for byte.

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

- **Status of the SOU-153 deliverables.** The original deliverables are implemented and
  validated here:
  - the comparator, run on existing public development reports and on synthetic
    controls, with no live model access or inference;
  - family-aware uncertainty;
  - the unknown contract;
  - outputs and controls.

  The additional requirement for an actual two-revision, source-bound comparison with
  frozen families is **not met** and stays subject to TL acceptance.
- **For TL review: no genuine two-revision comparison.** No public pair of matched/1
  reports from two source revisions exists (see the
  [inventory](#public-report-inventory)). The comparator has only been applied to
  synthetic controls and to the SOU-36 scripted-fixture reports of one revision. The
  retained public results are negative controls, and they do not satisfy the two-revision
  requirement. For the strongest pair (`6fe98d71` → `ad41af50`), the evidence is
  **missing**, not a comparator-produced result; see the
  [assessment](#two-revision-availability-assessment). A real comparison needs one
  recorded matched/1 run per revision, each with its own frozen plan with identical
  cases, plus a source bundle and frozen families. On the committed workspace development
  set it still could not give an interval.
- Latency remains descriptive, with no interval and no speed claim.
