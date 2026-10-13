# SOU-13 candidate dataset card

**Release status (2026-10-13):** 179-case CP2 Gold **privately released** under an approved Addendum v1 and internal-use-only export authorization. **NOT publicly released**; no data file is included in this repository.

**Use:** internal model training and evaluation **only**, under lead authorization `SOU13-USAGE-2026-10-12`
(2026-10-12). No public license has been granted; publication and redistribution are not authorized.

**License:** internal training/evaluation is authorized by the project lead; a public dataset license, publication and redistribution remain **unapproved**. The repository's Apache-2.0 license covers code, not automatically the private dataset.

## Purpose

Supervised multi-label classification of tool-call **semantic actions**. The labels are `read`, `write`,
`delete`, `send_data` and `change_permissions`, plus a separate Boolean `unknown`, under the SOU-10 v0.4
normative contract (`contract/updated_contract2.md`). The five action labels are tri-state: `true`, `false` or
`null`. Masks exclude nulls from known-label scoring.

## Composition and split

- The frozen pilot has 252 synthetic cases in 45 whole families.
- Splits: train 90, validation 54, calibration 54, sealed test 54.
- The development data is 19 CP1 cases plus 179 CP2 cases. The CP2 cases split into 71 train, 54 validation
  and 54 calibration.
- The held-out test split is nine restricted families. Their identities, test inputs and gold labels must not
  be public or accessible to model developers.
- Whole-family separation and the alias and near-duplicate graph checks are frozen. Do not recompute them for
  convenience.

A public copy of the source rebuilds a split over its 36 development families for structural tests only. That
recomputed split is not the frozen assignment.

## Source

CP2 semantics are AI-assisted synthetic programs with simulated interpreter and audit traces. Nothing executes
arbitrary MCP tools, sends external HTTP requests or touches production resources.

- A positive action is demonstrated relative to the declared program.
- A negative action is warranted only under a complete closed-program model after an audited execution.
  Q-CP2-DECL-EVIDENCE is resolved for exactly this reading, and only for the 179 CP2 development cases: no
  generalization to external calls, CP1 or the sealed test.
- `unknown=true` keeps the known positive actions; unproven actions remain `null`.

## Review

- 179 per-case technical self-consistency checks agree with the owner's 35 semantic rules.
- The owner attested inspection of 80 per-case evidence records.
- Six earlier cases were reviewed in one human batch.
- 93 cases were propagated from owner-approved rules and machine-checked per case.

The **Independent Dev Review Sign-off** (owner record, 2026-10-11) approved the semantics of all 179 CP2
development cases, including the six Q-FUTURE cases. An **approved private Gold Addendum v1** subsequently
confirmed exactly these 179 CP2 labels. The frozen source records retain historical statuses of 173 provisional,
6 pending and 0 confirmed: the additive release does not rewrite them. @iazizza separately reviewed the 54
sealed-test cases under independent custody before the once-only official SOU-16 evaluation.

A gold release must be a versioned gold addendum
([schema](../../../eval/sou13/schema/gold_addendum.schema.json)). It must be bound to the case ID and to the
evidence digests of the frozen label row, and it needs an independent reviewer's recorded approval. Owner
inspection, owner batch review and owner-rule propagation cannot confirm a label under that interface. Training
use needs a separate export authorization from the license owner
([gold development export](GOLD_DEV_EXPORT.md)).

## Integrity

The frozen split source and CP2 development package remain in the owner's private records. The final export's
ZIP SHA-256 is `24611b702c7242ad25bcf5e0d8bf4baecd8c19714fc014977976a9caadfa6237`; the separately
published export manifest SHA-256 is `78f0f539b80ebaee886f322fc71c530d18a1bb824f0de7edf96c5a08e832080d`.
@KAZDANTOK independently verified the export statement against the previously pinned owner signing key, with
`self_consistency=PASS` and `anchored_integrity=PASS` ([SOU-13](https://linear.app/soup-wall/issue/SOU-13)).
A package self-hash alone proves consistency, not origin or semantic label correctness.

## Recorded decisions (2026-10-11)

- **Independent Dev Review Sign-off:** received for all 179 CP2 development cases, including the six Q-FUTURE
  cases. It is not a gold release.
- **Internal ACL read:** 33 cases (replacing the earlier count of 17); the interpretation is agreed in the
  sign-off.
- **Internal keys enumeration:** the sign-off references 12 cases across `delete_prefix` and `user_offboard`.
  The 6 prefix `keys` cases listed earlier are a narrower subset; no further case mapping is inferred here.
- **Q-ADMISSION:** limited technical approval; clarified to apply within the agreed synthetic fixtures, including DEV09 / opaque admission; semantic labels confirmed. It is not a gold release, does not
  cover licensing, and adds no CP1 case to the gold scope.
- **Q-CP2-DECL-EVIDENCE:** resolved for the closed-program semantics of the approved 179 CP2 development cases only, where the absence of side effects is supported by the scenario audit; no generalization to external calls.
- **Sealed test custody:** confirmed; independent 54-case review and one authorized SOU-16 test run completed
  2026-10-12. Only case-free aggregates were shared with the model developer.

## Known limitations and unresolved approvals

- Q-CP2-DECL-EVIDENCE is resolved only for the closed-program semantics of the 179 CP2 development cases. Known
  `false` labels make no claim about external or real-tool effects.
- Other special-case interpretations of the contract.
- The 19 historical CP1 cases: excluded from Gold; on 2026-10-13 the lead directed a separate task for review.
- Public dataset licensing/publication/redistribution beyond the internal-use authorization: **not approved**.
- The separate Task 1 fixture-versioning ownership question is not resolved by the CP2 Gold release.
- The held-out evaluation is consumed; any future iteration requires a new independently approved test set.

An official **internal pilot** was evaluated once on the custodian-held 54-case sealed test set; the measured
aggregate and `REJECT` runtime-adoption recommendation are documented in [SOU-16](https://linear.app/soup-wall/issue/SOU-16).
That pilot is not production evidence and does not establish a production miss-rate guarantee. Training remains
authorized **only internally** (`SOU13-USAGE-2026-10-12`) on approved Gold development splits.

## Leakage boundary

Test data and labels stay in a private custodian process. Model authors may receive only approved development
data, subject to license and gold review. A one-shot sealed-test evaluation returns only authorized aggregate
metrics.
