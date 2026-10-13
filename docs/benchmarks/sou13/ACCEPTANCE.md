# SOU-13 acceptance status

**Status (2026-10-13): final documentation/lead acceptance pending.** The approved private Gold Addendum v1 and internal-use-only export authorization confirmed **179 CP2 development cases** (train 71 / validation 54 / calibration 54). The export was signed, delivered and independently verified by @KAZDANTOK. Frozen source row statuses were not rewritten. No private source, label rows or sealed test cases are in this repository.

On 2026-10-13 at 11:13 UTC+5 (Soup Wall General), project lead @winux125 instructed the owner to **update documentation and the checklist with verification links, after which AC2 and AC4 can be accepted for the approved CP2 scope**. The 19 historical CP1 cases are to be handled in a **separate task** and remain excluded from Gold. This is conditional scope approval, not final acceptance of the documentation PR or public dataset publication.

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

## Scope clarification (open)

**Task 1 fixture versioning (SOU-13 / SOU-21).** The SOU-10 contract schedules an update to synchronise
`fixtures/*.json` with D07 and D04, assigned to "SOU-13 / SOU-21"
([contract](../../../contract/updated_contract2.md), "Fixture Versioning & Evaluation"). The
[Task 1 report](../task1_classification_report.md) assigns the review of fixture updates for U07/CS03 (D07) and
E01 (D06) to SOU-13. This responsibility is **not covered** by AC1–AC4 above and is **not completed**. How
the work is split between SOU-13 and SOU-21 still needs an owner decision. The historical Task 1 run must be
preserved.

## Reviewer checklist

- [x] Q-ADMISSION: limited technical approval recorded (2026-10-11).
- [x] Sealed test custody confirmed (2026-10-11).
- [x] Independent Dev Review Sign-off received for all 179 CP2 development cases, including the six Q-FUTURE
      cases (2026-10-11).
- [x] Internal ACL read interpretation agreed (33 cases), and internal keys-enumeration interpretation agreed
      (12 cases across `delete_prefix` and `user_offboard`) (2026-10-11).
- [x] Q-CP2-DECL-EVIDENCE (closed-world negatives) resolved within a limited scope: the closed-program
      semantics of the 179 CP2 development cases only, supported by scenario audit; no generalization to external
      calls, CP1 or the sealed test.
- [x] Q-ADMISSION clarified: the limited technical approval applies within the agreed synthetic fixtures,
      including DEV09 / opaque admission; semantic labels confirmed. The gold scope stays the 179 CP2 cases.
- [ ] Other special questions are resolved, or explicitly excluded from the gold release.
- [ ] The 19-case legacy CP1 review is reconciled, without fabricating CP1 gold.
- [ ] Independent review of the sealed-test labels.
- [x] Internal-use scope recorded: `SOU13-USAGE-2026-10-12` authorizes internal model training and evaluation
      only (2026-10-12).
- [ ] Dataset licensing for any use beyond that scope (public license, publication, redistribution) and
      provenance are approved, and intended-use restrictions are documented.
- [x] The private full validation passed against the correct frozen data, and its ledger is recorded
      (owner-reported; aggregate ledgers; not inspected in this repository). The final run on commit `bdd1f92`
      (343 ran / 340 passed / 0 failed / 0 errored / 3 expected skips) covers the later test-only change in
      `test_obsolete_contract_binding_rejected`. Any later revision needs its own strict run
      ([private validation](PRIVATE_VALIDATION.md)).
- [ ] The SOU-13 / SOU-21 scope of Task 1 fixture versioning is decided, and the SOU-13 part is completed.
- [ ] The PR content is reviewed for safety, and the owner has authorized publication.
- [ ] A versioned gold release (addendum) is issued **only after** all applicable sign-offs. It is accepted only
      with independent-reviewer labels that match the labels being confirmed.
- [ ] Contract change under maintainer review: the proposed batch attestation (`independent_human_batch`)
      would let an independent reviewer's explicit batch approval of an exact, hash-identified artifact and case
      set confirm the frozen labels without per-case reviewer labels ([gold development export](GOLD_DEV_EXPORT.md)).
      Until it is approved, the per-case rule above applies.
- [ ] Any gold development export is built only from an approved addendum chain and
      an approved export authorization with license-owner and dataset-owner decisions. The authorization cites
      recorded decisions for every release question, as traceability only. A human release check confirms that
      each cited decision actually resolves its question ([gold development export](GOLD_DEV_EXPORT.md)). The
      tooling exists; no export has been authorised.

Maintainer review on October 12 fixed a dangling-symlink omission in the public-only privacy gate and
added one public regression. The frozen source modules, schemas and data were not modified. The public
suite now runs 344 tests: 194 pass and 150 named private-artifact skips. The owner-only 343-test ledger
above remains historical; it is not a strict private rerun of this later overlay.
