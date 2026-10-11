# SOU-13 candidate dataset card

**Release status:** NOT RELEASED. No data file is part of this repository.

**License:** PENDING an explicit dataset license and provenance sign-off. The repository's Apache-2.0 license
applies to the code. It does not apply automatically to the benchmark dataset.

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
- A negative action is warranted only under a complete closed-program model after an audited execution. This
  is subject to formal approval of Q-CP2-DECL-EVIDENCE.
- `unknown=true` keeps the known positive actions; unproven actions remain `null`.

## Review

- 179 per-case technical self-consistency checks agree with the owner's 35 semantic rules.
- The owner attested inspection of 80 per-case evidence records.
- Six earlier cases were reviewed in one human batch.
- 93 cases were propagated from owner-approved rules and machine-checked per case.

The **Independent Dev Review Sign-off** (owner record, 2026-10-11) approves the semantics of all 179 CP2
development cases, including the six Q-FUTURE cases. It is a confirmed semantic approval, not a gold release.
The frozen records keep their statuses: 173 provisional, 6 pending, **0 confirmed**. These change only through a
versioned gold release, which has not been issued. The sealed test labels have not been independently reviewed.

A gold release must be a versioned gold addendum
([schema](../../../eval/sou13/schema/gold_addendum.schema.json)). It must be bound to the case ID and to the
evidence digests of the frozen label row, and it needs an independent reviewer's recorded approval. Owner
inspection, owner batch review and owner-rule propagation cannot confirm a label under that interface.

## Integrity

The frozen logical split manifest and the CP2 development handoff each have a reference digest. These are held
in the owner's private records; neither the artifacts nor the digests are shipped. A package self-hash checks
consistency, not origin. Origin needs signature verification against an independently pinned owner key.

## Recorded decisions (2026-10-11)

- **Independent Dev Review Sign-off:** received for all 179 CP2 development cases, including the six Q-FUTURE
  cases. It is not a gold release.
- **Internal ACL read:** 33 cases (replacing the earlier count of 17); the interpretation is agreed in the
  sign-off.
- **Internal keys enumeration:** the sign-off references 12 cases across `delete_prefix` and `user_offboard`.
  The 6 prefix `keys` cases listed earlier are a narrower subset; no further case mapping is inferred here.
- **Q-ADMISSION:** limited technical approval only. It is not a gold release and does not cover licensing.
- **Sealed test custody:** confirmed. Sealed-test label correctness is still not verified.

## Known limitations and unresolved approvals

- Q-CP2-DECL-EVIDENCE: closed-world negatives and the masked-negative interpretation. This is a separate,
  open interpretation question; it does not withdraw the semantic sign-off of the 179 development cases.
- Other special-case interpretations of the contract.
- The 19-case CP1 legacy review.
- Versioned gold release (**pending**; no addendum issued).
- Independent review of the sealed-test labels.
- Separate dataset licensing (**pending**).
- One-shot sealed-test evaluation protocol.

No official model benchmark, test score, production behavior or training authorization is claimed.

## Leakage boundary

Test data and labels stay in a private custodian process. Model authors may receive only approved development
data, subject to license and gold review. A one-shot sealed-test evaluation returns only authorized aggregate
metrics.
