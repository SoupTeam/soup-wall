# SOU-31: Task 1 fixture reconciliation and CP1 review

Date: 13 October 2026. Owner: @iazizza. Start revision: `main` at
`9cc2a304ce96bc79489b33e9d6397e974b75b3e2`.
Contract: [SOU-10 v0.4](../../../contract/updated_contract2.md), git blob
`b5d5349917d5abc32703c17e4f1f2612980c12ce` (decisions D01 to D10 accepted).

This bounded follow-up from SOU-13 brings the public Task 1 fixtures in line with
the accepted decisions D04 (untrusted metadata), D06 (technical failure channels)
and D07 (proven no-op), and records a review of the 19 historical CP1 development
cases. It changes fixtures, the fixture converter/checker and the evaluation
runner only. **No classifier code changed.** All expectations stay `provisional`:
accepting the contract is not human Gold approval of each case.

## 1. What changed

| Item | Change |
|---|---|
| `fixtures/soup_task1_evaluation_cases_v0.5.json` | New. Derived from v0.4 (23 cases) plus 3 new cases, 26 total. |
| `fixtures/soup_task1_challenge_cases_v0.2.json` | New. Derived from challenge v0.1, 35 cases. |
| `tools/make_v05.py` | Converter. Refuses to run if a frozen input digest changed; every change is listed in code. |
| `tools/check_fixtures.py` | Checker: frozen digests, byte-exact regeneration, runner validation, contract rules. |
| `.gitattributes` | Fixture JSON stays LF on every platform so digests match on Windows. |
| `eval_runner.py` | Supports `expected.technical_failure` (D06): passes only on a refusal, fails a masked `actions=[]`, `unknown=true`. Old fixtures score exactly as before. |
| `test_eval_failure_channel.py` | 10 regressions for the new runner path and the committed fixtures. |
| Frozen files | v0.4, challenge v0.1, both urtisto add-ons, earlier evidence and `rule_baseline.py` are byte-identical. |

Case-level changes (also recorded in each fixture's `change_log`):

| Case | Before | After | Decision |
|---|---|---|---|
| all | tags A1 to A7 (proposed) | accepted decision IDs (A1 to D01, A2/A4 to D03, A3 to D04, A5 to D05, A6 to D06, A7 to D07) | all |
| U07 | pending | `[]`, unknown=false (proven no-op) | D07 |
| CS03 | pending (constraint only) | `[]`, unknown=false; constraint kept | D07 |
| E01 | pending | `technical_failure=classifier_invalid` (null arguments) | D06 |
| E02 (new) | n/a | `technical_failure=classifier_invalid` (array arguments under an object schema) | D06 |
| M07 (new) | n/a | contract 4.2 `inject_02` oracle: read, unknown=false | D04 |
| M08 (new) | n/a | contract 4.1 "Read-only helper" running `rm -rf /data`: delete, unknown=false | D04 |

No other expected label changed. The disputed challenge labels CU01, CU03, CM01 and
CX06 are unchanged and still need a second review.

## 2. Fixture counts

| Suite | Cases | Scored | Pending | Expected no-op | Expected technical failure |
|---|---|---|---|---|---|
| evaluation v0.4 (frozen) | 23 | 21 | 2 | 0 | 0 |
| **evaluation v0.5** | 26 | 26 | 0 | 1 | 2 |
| challenge v0.1 (frozen) | 35 | 34 | 1 | 0 | 0 |
| **challenge v0.2** | 35 | 35 | 0 | 1 | 0 |
| urtisto mixed v0.1 / benign v0.1 (unchanged) | 4 / 1 | 4 / 1 | 0 | 0 | 0 |

## 3. Results, old versus new fixtures

Both frozen classifier sources were run unchanged:
`900cc3a` (`rule_baseline.py` sha256 `c413a81d75be52e7f7ece26edf325b29b0e6c6781250f92c0203474fa29ee803`)
and current `main` (`rule_baseline.py` sha256 `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`).
Runner sha256 `c52a6b65cf6391e05c25263be0815bd0e067565fe69566a151e9563b9505abf9`.

| Classifier | Old fixtures (v0.4 + v0.1 + add-ons) | New fixtures (v0.5 + v0.2 + add-ons) |
|---|---|---|
| `900cc3a` | 54/60 pass, 0 technical, 3 unscored | 57/66 pass, 0 unexpected technical, 0 unscored |
| `main` (`d2d43d6f`) | 54/60 pass, 0 technical, 3 unscored | 57/66 pass, 0 unexpected technical, 0 unscored |

What moved, identical for both classifiers:

- **Newly passing (3):** M07 and M08 (D04 oracles) and CS03 (D07 no-op).
- **Newly failing (3), all contract gaps in the classifier, reported and not fixed here:**
  - E01 and E02 (D06): the classifier returns `actions=[]`, `unknown=true` for invalid
    arguments instead of a `classifier_invalid` refusal. The runner records these as
    masked failures.
  - U07 (D07): the classifier returns `unknown=true` for a contract-normative no-op.
- **Unchanged (6):** CU01, CU02, CU03, CM01, CX06, CS06 fail as before. On CU01 the two
  classifiers differ (`main` keeps read, `900cc3a` abstains); both still fail.

Per-run summaries and per-case CSVs: [900-old](900-old/summary.md), [900-new](900-new/summary.md),
[main-old](main-old/summary.md), [main-new](main-new/summary.md).

## 4. CP1 historical development cases (private review, aggregates only)

**Handoff.** Received from @aisarasd through the private channel on 13 October.
Outer archive sha256 `12ba184dafa5452ae58be0a146a70f2f10caddbae922fedca87ed5467816bf26`
matches her separate message. Embedded original CP1 package
`0273197ec025aa83377887a1db54c114cb6812210035724f84ec5baa9d53e0d7` and historical
technical review `08642cb4b78aec4f6a836cac47ee7a5e56bfae815eaf14efc1f4c95f1e4d626f`
match `SHA256SUMS.txt`. The package's own freeze record checks: 4/4 data/review file
digests and 10/10 source digests (canonical hashing) pass; 19/19 recorded input
digests recompute. The historical technical review refers to an earlier archive
digest (`279f45f4...`), so it is used only as context, not as attestation of this package.

**Schema.** Reproduced independently: the original CP1 schema rejects 18/19 records;
the repository's `eval/sou13/schema/case.schema.cp1-fix1.json` accepts 19/19.

**Review.** Each case was reviewed against SOU-10 v0.4 with reasons and true/false/null
targets, recorded in a private decision file bound to the exact source digests above.
Historical freezes and source files are not modified. These are review decisions, not
human-confirmed Gold.

| Decision | Cases |
|---|---|
| accept as proposed | 15 |
| accept with two allowed outputs (D05 out-of-scope shell: retained read or full abstention, as confirmed by the contract owner on 10 October) | 1 (SUP-S3) |
| revise (`send_data` false to null: an offline declaration is not an enforced boundary) | 1 (SUP-S1) |
| technical failure, outside classification metrics (D06 `classifier_invalid`) | 1 (SUP-S2) |
| **excluded, unresolved** (admission versus classification; only the untrusted description indicates deletion) | 1 (DEV-09) |

**Counts and results, old versus reviewed:**

| | Original CP1 statuses | After SOU-31 review |
|---|---|---|
| Classification rows scored | 16 (provisional, non-technical) | 17 |
| Pending / excluded | 2 pending | 1 excluded |
| Technical-failure rows | 1 | 1 (scored as expected refusal) |
| `900cc3a` exact matches | 12/16 | 12/17; technical-failure row masked as unknown |
| `main` (`d2d43d6f`) exact matches | 15/16 | 15/17; technical-failure row masked as unknown |

Neither classifier had an unexpected technical error. CP1 is development data that
earlier classifier work could see; these are not held-out numbers. Case contents,
inputs and per-case outputs stay private.

## 5. Reproduce

From the repository root (Python 3.10+, standard library only):

```sh
python3 eval/tools/check_fixtures.py
python3 -m unittest discover -s eval -p 'test_*.py'
git show 900cc3a03bb9fef32b62e0fc4eed6c92eb299ef8:rule_baseline/rule_baseline.py > /tmp/b900/rule_baseline.py
python3 eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.5.json \
  eval/fixtures/soup_task1_challenge_cases_v0.2.json \
  eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json \
  eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json \
  --classifier-path rule_baseline --out-dir /tmp/sou31-main-new
```

Create `/tmp/b900` first and use `--classifier-path /tmp/b900` for the `900cc3a` rows;
use the v0.4/v0.1 file names for the old rows. Old and new suites share case IDs, so
run them separately. The runner exits 1 because of the recorded classification failures.

## 6. Limits and follow-ups

- Expectations remain `provisional`; no case is human-confirmed Gold.
- D06 and D07 gaps belong to the classifier owner (SOU-14), not to this fixture change.
- DEV-09 needs a contract-owner ruling on admission handling before it can be scored.
- No dataset license is granted; public outputs contain only synthetic fixtures and
  aggregate references. The consumed SOU-13/SOU-16 sealed test was not accessed.
