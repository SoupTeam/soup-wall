# SOU-34: generic classifier revision generic_rule_v2

Date: 14-15 October 2026. Owner: @Sundetali7. Start revision: `main` (SOU-31 fixtures, SOU-14 closed).
Contract: SOU-10 v0.4 (D04 untrusted metadata, D06 technical failure channels, D07 proven no-op).

## Scope and claims

- New file `rule_baseline/rev2/rule_baseline.py`, `REVISION = "generic_rule_v2"`, sha256
  `d0b4fc02720ee5ff38dec73d5992c6bdee9eda8595282e33015e60d07ce33ea5`.
- Frozen, untouched: `rule_baseline/rule_baseline.py` sha256 `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`
  (the SOU-14 held-out result is bound to it), earlier reports, fixtures, `eval/eval_runner.py`
  (sha256 `86dded74283e7dc38e3ea8b2996a8cccf900912ccb847ea0fdad482abcbd0662`).
- **No generalization claim.** All numbers below are development or public-fixture numbers. The sealed
  SOU-13/SOU-16 test was not opened, run or used. The revision is not enabled in production admission.
  Not in scope: fixture relabelling, runtime grants, policy floors, constrained execution.
- Dev numbers are optimistic: the dev families (ack, offboard, reassign) motivated part of the vocabulary.

## Public fixtures, frozen versus rev2

Fixtures: evaluation v0.5 (26), challenge v0.2 (35), urtisto mixed (4), urtisto benign (1); 66 cases.
Command: `python3 eval/eval_runner.py <four fixtures> --classifier-path <dir> --out-dir <out>`; full outputs
are in `public_fixtures_frozen/` and `public_fixtures_rev2/`.

| | frozen d2d43d6f | rev2 |
|---|---|---|
| pass | 57/66 | 60/66 |
| evaluation v0.5 | 23/26 | 26/26 |
| challenge v0.2 | 29/35 | 29/35 |
| critical misses | 1 | 1 |
| unknown reported | 14/66 (expected 7) | 11/66 (expected 7) |
| technical failures counted as failures | E01, E02 are masked classifications | 0 (both are `classifier_invalid`) |

Changed cases: E01, E02 (D06) and U07 (D07) now pass. Still failing in both, unchanged: CU01, CU02, CU03,
CM01, CX06, CS06 (the disputed challenge labels and one critical miss are not addressed here).

Per-label errors on the 66 public cases (known true / missed / extra), identical for both: read 32/2/0,
write 11/1/0, delete 14/1/0, send_data 11/0/0, change_permissions 9/0/0. The public fixtures hold none of
the new vocabulary families, so they show no per-label change; the gain is in failure channels and U07.

## SOU-13 development exports (188 cases, provisional labels, exports DRAFT)

Command: `python3 rule_baseline/evaluate_dev.py --exports <exports> --classifier rule_baseline/rev2/rule_baseline.py
--baseline rule_baseline/rule_baseline.py --baseline-label frozen_d2d43d6f --out-dir <out>`. Full report in
`dev_exports/EVALUATION.md` and `dev_exports/evaluation.json`.

| Measure | frozen | rev2 |
|---|---|---|
| contract match | 143/188 | 172/188 |
| silent risky-label misses (cases) | 6 | 0 |
| coverage (answered without unknown) | 118/188 (63%) | 141/188 (75%) |
| unknown on cases labelled known | 29 | 6 |
| mixed cases with all actions found | 16/28 | 28/28 |
| technical failures | 0/188 | 0/188 |

Per label (known true / missed / extra): write 35/12/2 -> 35/6/2, delete 29/12/0 -> 29/0/0,
send_data 38/0/6 -> 38/0/0, change_permissions 36/6/0 -> 36/0/0, read 35/0/0 -> 35/0/0. The 6 remaining
write misses are flagged `unknown=true`.

Batch-1 latency (ms, valid exchanges, p50 / p95 / max): `classify()` in process 0.212 / 0.378 / 1.617
(frozen 0.175 / 0.346 / 2.32); warm snapshot process 0.497 / 0.82 / 54.79 (0.453 / 0.735 / 46.77);
new process per call 70.2 / 113.7 / 116.8 (57.9 / 72.5 / 80.6). No call over 1500 ms. Single environment,
not a bound on daemon latency.

## Review fix (PR 115, requested changes at 4c3f80c)

`_schema_violation` now reads the same normalised schema as `_object_schema` and `_pure_definition`
(plain, `inputSchema` or `input_schema`). Before, a wrapped schema was used for D06 and the no-op proof but not
for the violation check, so `checksum_text` with `{}` or `{"text": 9}` under a wrapped schema was reported as a proven
no-op. Now D06, the violation diagnostic and the no-op proof use one schema. Four regressions
(`WrappedSchemaSpellings` in `test_rev2.py`) cover valid, missing-required, wrong-type and extra-property
arguments for all three spellings and for both `tool_schema` and `pinned_schema`, plus non-object arguments and a
pinned schema chosen over a permissive tool schema; the invalid-arguments control fails on the previous revision bytes.
The revision bytes changed, so all source-hash-bound evidence was regenerated: the public-fixture results and
the development evaluation below are unchanged except the latency samples and the revision digest. The frozen candidate
digest is unchanged.

## Remaining defects (not fixed here)

- 16 of 188 dev cases still differ from the label: `fam.unknown.plugin_job` (6, got no action + unknown),
  `fam.no_effect.rollout_plan` (6, stays unknown: only a bounded name vocabulary proves no-op),
  `fam.unknown.vendor_bridge` (2), `fam.write.migration_apply` (2, label question).
- Field-level schema violations with an object argument stay partial unknown; only non-object arguments
  under an object schema become `classifier_invalid`.
- The no-op vocabulary is narrow by design; names outside it stay `unknown=true`, which is the safe side.
- One frozen test expectation differs by design: `ack_message` is `delete` in rev2 (it is `unknown` in the
  frozen file, covered by `test_generalization.py`, which keeps testing the frozen file only).

## Reproduce

```
python3 -m unittest discover -s rule_baseline -p "test_*.py"
python3 eval/tools/check_fixtures.py
python3 eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.5.json eval/fixtures/soup_task1_challenge_cases_v0.2.json eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json --classifier-path rule_baseline/rev2 --out-dir out_rev2
```
