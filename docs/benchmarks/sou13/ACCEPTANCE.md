# SOU-13 acceptance status

**No acceptance criterion is claimed as met.** This page separates the technical evidence the repository can
reproduce from the decisions that only named people can make.

The 179 CP2 development cases have received **independent semantic sign-off**. That is not a gold release. The
frozen records and their statuses are unchanged, and labels become gold only through a versioned gold release
(addendum). None has been issued. Passing tests, matching digests and mechanical rule agreement are technical
evidence, not a license or a release decision.

## Recorded decisions

These are owner decision records dated 2026-10-11, plus later recorded clarifications. The records themselves
are kept outside the repository; their decision ids and dates are not reproduced here.

| Question | Recorded decision | What it does **not** decide |
| --- | --- | --- |
| Independent Dev Review Sign-off | **Received for all 179 CP2 development cases.** It covers the six Q-FUTURE cases, the internal ACL read interpretation and the internal keys-enumeration interpretation (rows below). | It is not a versioned gold release; no addendum is issued and the frozen statuses are unchanged. It does not resolve Q-CP2-DECL-EVIDENCE, the CP1 legacy review, licensing, the sealed test or publication. |
| Internal ACL read | **33 cases** (replacing the earlier count of 17). The interpretation is **agreed** in the sign-off. | — |
| Internal keys enumeration | The sign-off references **12 cases across `delete_prefix` and `user_offboard`**. The 6 prefix `keys` cases listed earlier are a narrower subset of these. | This page infers no further case-to-family mapping. |
| Q-ADMISSION | **Limited technical approval**, within the scope stated in the owner record. **Clarified** by the contract owner and independent reviewer (Nari AB): it applies within the agreed synthetic fixtures, including DEV09 / opaque admission; semantic labels confirmed. | It is not a gold release and does not cover licensing or release. It does not add DEV09 or any other CP1 case to the gold scope. |
| Q-CP2-DECL-EVIDENCE | **Resolved within a limited scope** by the contract owner and independent reviewer (Nari AB): known `false` labels are confirmed for the closed-program semantics of the approved 179 CP2 development cases only, where the absence of side effects is supported by the scenario audit; no generalization to external calls. | It covers no CP1 case, no sealed-test case and no external tool call. |
| Sealed test custody | **Test custody confirmed.** The 54-case sealed test package is held under the custodian process. | Sealed-test label correctness is still **NOT VERIFIED**. Independent test-label review and the one-shot evaluation protocol are pending. |
| Internal use (`SOU13-USAGE-2026-10-12`, lead authorization, 2026-10-12) | **Internal model training and evaluation only.** Recorded as Telegram Soup Wall message 653, 2026-10-12 11:43 UTC+5. | It is not a public license and does not authorize publication or redistribution; both remain undecided. It is not a gold release: it resolves no label, open question, Q-CP2-DECL-EVIDENCE or the CP1 legacy review, and it never makes the sealed test available. |

## Criteria

| Criterion | Technical evidence available | Status | Remaining blockers |
| --- | --- | --- | --- |
| AC1: pilot diversity and size | 252 frozen cases in 45 families; 19 CP1 and 179 CP2 development cases; 54 sealed test cases (owner-local) | Not claimed | Validate the final released gold denominators |
| AC2: high-quality, reviewed labels | **Independent semantic sign-off of all 179 CP2 development cases**; 35 owner semantic rules with 179 mechanical agreements; limited technical Q-ADMISSION approval; gold-addendum interface | **Not met** | Q-CP2-DECL-EVIDENCE resolved for the 179 CP2 cases only (scoped clarification); 19-case CP1 legacy review; **versioned gold release (pending)**. The frozen records remain 173 provisional / 6 pending / 0 confirmed until that release. |
| AC3: frozen, disjoint splits and custody | Family-disjoint split, immutable manifest and anchor; sealed package technically verified; **test custody confirmed** | Not claimed | Independently pinned owner key; one-shot evaluation protocol; **independent sealed-test label review (pending)** |
| AC4: reproducible handoff, documentation and PR | Source byte-identical to both freezes; public data-free suite; privacy gate; [private validation procedure](PRIVATE_VALIDATION.md); owner-reported private strict validation PASS (2026-10-12): 343 ran / 340 passed / 0 failed / 0 errored / 3 skipped; source identity PASS; freeze anchor verified; privacy gate PASS | **Not met** | Exact-head PR CI; **dataset licensing and provenance (pending)**; owner approval to publish |

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
