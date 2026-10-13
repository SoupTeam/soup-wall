# SOU-13 acceptance status

**Status (2026-10-13): final documentation/lead acceptance pending.** The approved private Gold Addendum v1 and internal-use-only export authorization confirmed **179 CP2 development cases** (train 71 / validation 54 / calibration 54). The export was signed, delivered and independently verified by @KAZDANTOK. Frozen source row statuses were not rewritten. No private source, label rows or sealed test cases are in this repository.

On 2026-10-13 at 11:13 (Soup Wall General), project lead @winux125 instructed the owner to **update documentation and the checklist with verification links, after which AC2 and AC4 can be accepted for the approved CP2 scope**. The 19 historical CP1 cases are to be handled in a **separate task** and remain excluded from Gold. This is conditional scope approval, not final acceptance of the documentation PR or public dataset publication.

**Official test status:** @iazizza reviewed the 54 held-out cases and completed one authorized test run for [SOU-16](https://linear.app/soup-wall/issue/SOU-16). Restricted test gold and per-case results remain with the custodian.

## Recorded decisions

These are owner decision records dated 2026-10-11, plus later recorded clarifications. The records themselves
are kept outside the repository; their decision ids and dates are not reproduced here.

| Question | Recorded decision | What it does **not** decide |
| --- | --- | --- |
| Independent Dev Review Sign-off | **179/179 CP2 development labels signed off** by Nari AB; six Q-FUTURE and internal bookkeeping interpretations included. An approved private Gold Addendum v1 then bound that sign-off to the 179-case release. | Batch approval is not 179 individual independent reviews; no CP1 or test Gold implied. |
| Internal ACL read | **33 cases** (replacing the earlier count of 17). The interpretation is **agreed** in the sign-off. | — |
| Internal keys enumeration | The sign-off references **12 cases across `delete_prefix` and `user_offboard`**. The 6 prefix `keys` cases listed earlier are a narrower subset of these. | This page infers no further case-to-family mapping. |
| Q-ADMISSION | **Limited technical approval**, within the scope stated in the owner record. **Clarified** by the contract owner and independent reviewer (Nari AB): it applies within the agreed synthetic fixtures, including DEV09 / opaque admission; semantic labels confirmed. | It is not a gold release and does not cover licensing or release. It does not add DEV09 or any other CP1 case to the gold scope. |
| Q-CP2-DECL-EVIDENCE | **Resolved within a limited scope** by the contract owner and independent reviewer (Nari AB): known `false` labels are confirmed for the closed-program semantics of the approved 179 CP2 development cases only, where the absence of side effects is supported by the scenario audit; no generalization to external calls. | It covers no CP1 case, no sealed-test case and no external tool call. |
| Sealed test custody | Custody confirmed; @iazizza independently reviewed the 54-case sealed test and completed **one official authorized SOU-16 run** (2026-10-12). | No raw test inputs/labels or per-case predictions released to model authors. |
| Internal use (`SOU13-USAGE-2026-10-12`) | **Internal training and evaluation only**, under the project lead's 2026-10-12 decision (Soup Wall General message 653). | No public license, publication or redistribution authorization. |

## Criteria

| Criterion | Current evidence | Status / next action |
| --- | --- | --- |
| **AC1: pilot diversity and size** | Frozen **252-case / 45-family** pilot, including 179 CP2 dev, 19 historical CP1 and 54 sealed-test cases. | **Checked in [SOU-13](https://linear.app/soup-wall/issue/SOU-13)**; approved Gold release covers CP2 dev only. |
| **AC2: reviewed labels, masks and evidence** | Nari AB's independent **179/179 CP2** sign-off and scoped clarifications; versioned approved Gold Addendum v1 binds the exact frozen case/label hashes. Recipient confirms 179 approved CP2 cases. | **Ready for lead acceptance for CP2** after this documentation update/review. The 19 CP1 cases are deferred by lead decision (2026-10-13); no CP1 Gold is claimed. |
| **AC3: frozen family-held-out splits** | Original signed frozen split, independently pinned owner key and development export scoped to **71 train / 54 validation / 54 calibration** CP2; independent custodian holds the **54** sealed-test cases. | **Checked in [SOU-13](https://linear.app/soup-wall/issue/SOU-13)**; no re-freeze or repeat test. |
| **AC4: reproducibility, documentation, provenance and PR** | Owner-reported final current-source strict validation **445 run / 441 passed / 0 failures / 0 errors / 4 expected Windows skips**; [PR #85](https://github.com/SoupTeam/soup-wall/pull/85) and [PR #87](https://github.com/SoupTeam/soup-wall/pull/87) merged after 24 checks; signed export and receipt verification PASS; [dataset card](DATASET_CARD.md), [workflow](GOLD_DEV_EXPORT.md), [private validation](PRIVATE_VALIDATION.md) and this checklist updated. | **Ready for lead acceptance for CP2** after docs PR review/merge. Internal-use-only permission recorded. Public dataset licensing/publication not granted or claimed. |

### Exact handoff and verification references

- Final private Gold ZIP SHA-256: `24611b702c7242ad25bcf5e0d8bf4baecd8c19714fc014977976a9caadfa6237`.
- Export manifest SHA-256 (separately communicated outside archive): `78f0f539b80ebaee886f322fc71c530d18a1bb824f0de7edf96c5a08e832080d`.
- Signed export: independent `self_consistency=PASS`, `anchored_integrity=PASS` and matched owner key as recorded by @KAZDANTOK in his final [SOU-13 handoff comment](https://linear.app/soup-wall/issue/SOU-13). The archive content, addendum and authorization were verified without executing archived scripts.
- Source/tooling: reviewed [PR #80](https://github.com/SoupTeam/soup-wall/pull/80), accepted batch-attestation + export tooling [PR #85](https://github.com/SoupTeam/soup-wall/pull/85), verifier containment fix [PR #87](https://github.com/SoupTeam/soup-wall/pull/87); downstream model converter [PR #88](https://github.com/SoupTeam/soup-wall/pull/88). Frozen private source remains unchanged.
- Source/reviewer/usage: [SOU-13 decision records](https://linear.app/soup-wall/issue/SOU-13) include Nari AB's 179-case sign-off, closed-world negatives and opaque admission clarification, owner report, and `SOU13-USAGE-2026-10-12` lead permission for internal training/evaluation only.
- Downstream once-only custodian test and measured review: [SOU-16](https://linear.app/soup-wall/issue/SOU-16). Test scores are experimental classifier outcomes, **not** a guaranteed dataset-quality score or a production safety claim.

## Deferred work and scope boundaries

- **CP1:** On 2026-10-13 at 11:13, @winux125 directed a separate task for the **19 historical CP1** cases. They are excluded from the Gold development release and their labels are **not** certified here.
- **Task 1 fixture versioning:** The [SOU-10 contract](../../../contract/updated_contract2.md) names SOU-13 / SOU-21 for `fixtures/*.json` synchronization with D07/D04. The [Task 1 report](../task1_classification_report.md) also mentions U07/CS03 and E01. The October 13 CP1 scope decision did **not expressly assign or complete this fixture task**. Its ownership/follow-up remains separately open; preserve the historical Task 1 runs and do not silently assert completion.
- **License:** `SOU13-USAGE-2026-10-12` is internal-use permission only; a future public release, reuse or redistribution requires a distinct approval.
- **Sealed-test:** @iazizza approved and ran the official one-shot experiment on 2026-10-12 for SOU-16. This does not expose the sealed inputs, prove production safety, or permit an additional evaluation on the same held-out set.

## Final CP2 scope checklist

- [x] Frozen pilot and disjoint train/validation/calibration/test manifests prepared and pinned.
- [x] Independent Nari AB CP2 development sign-off and scoped Q-ADMISSION / Q-CP2-DECL-EVIDENCE / Q-FUTURE interpretations recorded.
- [x] Accepted artifact-bound `independent_human_batch` contract, approved private Gold Addendum v1 and approved internal-only export authorization.
- [x] Approved 179-case CP2 development export signed and independently verified by its recipient; 19 CP1 and sealed test excluded.
- [x] Strict owner private validation PASS (445/441/0/0/4); accepted public PRs and verifier path-scope fix merged.
- [x] Custodian custody, independent 54-case review and one authorized sealed-test run recorded in SOU-16.
- [x] Historical CP1 review deferred to a separate task by project-lead decision (2026-10-13); no CP1 promotion.
- [x] Restrictions documented: internal training and evaluation only; no public dataset licensing or publication.
- [ ] **This documentation/checklist update reviewed and merged, then AC2 and AC4 formally accepted for CP2 by the lead.**

**SOU-13 remains `In Progress` until the final documentation review and lead acceptance.** The original signed freezes, frozen label statuses and restricted source/decision records are unchanged. The repository records the reproducible code and safe evidence references, not the private dataset or sealed-test contents.
