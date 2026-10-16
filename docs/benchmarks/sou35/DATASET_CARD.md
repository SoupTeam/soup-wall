# SOU-35 candidate dataset card

**Status (2026-10-15): private candidate pool, NOT released.** This repository contains no real SOU-35 candidate
data: no private family declaration, invocation record, seed or sealed-test identity. It includes only three
clearly artificial toy declarations (`eval/sou35/tests/toy/`, `artificial_toy: true`) used by tests. No label is
human-approved or Gold. No data-use permission, license or independent semantic review approval has been
granted for SOU-35. The team lead designated the dataset owner as sealed-test custodian on October 15. Development/test membership is **undetermined**.

## Purpose

A fresh, family-held-out synthetic benchmark for tool-call **semantic action** classification under the SOU-10 v0.4
contract ([`contract/updated_contract2.md`](../../../contract/updated_contract2.md)). It replaces nothing in SOU-13:
the SOU-13/SOU-16 sealed test was evaluated once and is consumed, so a new held-out split needs new families.

Labels: `read`, `write`, `delete`, `send_data`, `change_permissions` (each `true`, `false` or `null`), a separate
Boolean `unknown`, and the D06 technical-failure channel `classifier_invalid` for inputs that violate the admitted
schema.

## What exists and what does not

| Item | State on 2026-10-15 |
| --- | --- |
| Generated candidate records | Yes: private, outside Git, not released |
| Labels | Mechanically derived; every record `provisional` or `pending`; 0 confirmed |
| Human-reviewed SOU-35 decisions | None |
| Frozen split / test-family draw | None; every record is `split: unassigned` |
| Released or exported dataset | None |

## Composition

The candidate pool meets the SOU-35 minimum size and family-diversity requirements: at least 120 tool-invocation
cases from at least 12 semantically distinct families, each family with one schema-violating technical-error case.
Exact pool totals, family names, behaviours, the candidate list, label-status breakdowns and per-family or per-label
counts are **withheld** until disclosure is approved: once development families are published, any pool-level figure
minus the public development figure becomes a figure about the restricted test split. The exact aggregates are kept
in the dataset owner's ignored workspace.

## Methodology

- **Semantics as data.** Each family is one synthetic implementation, declared as JSON: admitted identities
  (server, tool name; one alias per family), honest and misleading descriptions, an admitted object schema, and a
  closed program for the frozen SOU-13 CP2 declarative interpreter (`eval/sou13/sou13cp2/semantics.py`, digest
  pinned by `eval/sou13/tests_cp2/test_freeze_inventory.py`). Nothing real is executed.
- **Labels are derived mechanically.** The interpreter runs the program on the case arguments with a typed access
  audit and state-diff check; the reused SOU-13 function `labels_from_execution` maps effect events to `true`,
  complete audited absence to `false`, and an unmodelled component to `null` with `unknown=true`. Each family also
  declares its expected labels per template; generation fails on any disagreement.
- **Case design.** Per family: several argument-selected behaviours where the program has them, a null description
  (SOU-10 §1.2), a misleading description (D04), an alias identity, action words inside argument data (§2 rule 3),
  and one schema-violating input (D06). Case order is shuffled with a private seed.
- **Novelty and leakage.** Every family is compared with the 36 public SOU-13 development families and with the
  rest of the pool on identity, server, normalised name, description, template signature, field-name-insensitive
  shape and program skeleton (reused `sou13cp2.identity`/`leakage`). Current result: no link, no near-duplicate.
- **Split feasibility.** Whole leakage groups are allocated; every held-out split must contain a positive and a
  known negative for each action, an unknown case, a proven no-op and a technical-error case. Requirements are never
  relaxed; impossible ones are reported. Only counts are computed; no split is frozen and no draw has been made.

## Provenance

Synthetic and AI-assisted (`annotator: ai_assisted_synthetic_draft`). Domains are `example.test`, phone numbers are
reserved `+1555-01xx` values, and secrets are `ref:placeholder-NN` strings. No production data, no SOU-13 data file
and no SOU-13/SOU-16 sealed material was used or opened; the tooling refuses to run when that material is present.

## Evidence limitations

- A positive label is demonstrated only relative to the declared synthetic program.
- A `false` label means "absent in the closed synthetic program after a clean audit". The SOU-13 ruling accepting
  this reading (Q-CP2-DECL-EVIDENCE) was scoped to the 179 SOU-13 CP2 cases and is **not** transferred to SOU-35.
- The same author wrote each program and its expected labels: the cross-check shows internal consistency, not
  semantic truth. AI-assisted technical review never confirms labels.
- Overlap with the restricted SOU-13 test families cannot be checked without that custodian.
- Held-out splits will hold a few families each; results will be family-level evidence with wide uncertainty.

## Label statuses and decisions still open

Labels stay `provisional` or `pending` (a record is `pending` when it depends on an unresolved semantic ruling). The
case schema has no `confirmed` status and requires `human_semantic_approval: null`, so no record of this version can
be Gold.

| Id | Open decision |
| --- | --- |
| Q-S35-DECL-EVIDENCE | Are closed-program `false` labels acceptable for SOU-35? |
| Q-S35-INTERNAL-ACCESS | Is an internal ACL read or key listing inside a permission change / prefix delete not `read`? |
| Q-S35-EMPTY-BATCH | Is an empty batch a proven no-op? |
| Q-S35-UNMODELLED-MODE | Is an unlisted mode value full unknown? Unknown coverage of every held-out split depends on it. |
| Q-S35-OPTIONAL-DEFAULT | Does an absent optional flag take the declared default branch? |
| Q-S35-HUMAN-REVIEW | Independent human semantic reviewer: not assigned. |
| Q-S35-DATA-USE | Data-use permission: not granted. No license is assumed. |
| Custody | Dataset owner named custodian by team lead; test-family draw and split freeze not performed. |

## Roles and trust boundary

Tooling exists (toy-tested only) for sealed-test custody, a versioned family-disjoint split manifest, and a gated
development export. None of it has been run on the candidate pool.

- **Sealed-test custodian (dataset owner, assigned by team lead).** Runs commit, draw, accept, freeze and the development export
  (`python -m sou35.release`). Holds the custodian seed, the draw nonce, the test-family list and the **full
  manifest**, which names test families. None of these may leave the custodian's ignored `sealed/` workspace.
- **What leaves custody.** Only the public manifest view (development families, test counts and sha256
  commitments) and the development export (train/validation/calibration only; only case-evidence-reviewed,
  externally authorised classification records are exported; unresolved/technical records are excluded). Tests confirm neither contains
  test family ids, test case ids, the seed, the nonce or the full manifest's frozen assignment.
- **Approvals are recorded, not authenticated.** `approved_by`, the custodian acceptance and the export
  `authorized_by` are text supplied by the operator, then bound into sha256-digested documents. A digest proves the
  document has not changed since; it does not prove which person decided. Nothing is cryptographically signed (the
  SOU-13 signed-anchor procedure is not adopted here). A private pool-bound rulings register records externally verifiable decision references, along with
  per-case evidence-review digests. This binds a claimed review to exact records but is not a signature or a Gold
  addendum. The named independent reviewer and data-use authority must be verified outside the code.

## Fail-closed release controls (not yet run on real data)

A versioned, **private** rulings register must bind to the declaration-pool digest and contain accepted decisions
for any questions affecting a scored record plus case-level evidence-review attestations bound to each exact
record digest. Missing, pending, rejected or unreviewed cases cannot count towards accepted split coverage and are
excluded completely from development exports. Real `accepted` entries must be transcribed from independently
recorded human decisions, never created automatically.

The v2 full manifest binds the canonical record inventory and the rulings register. Custody commitments bind the
register before drawing test families. The library and CLI require the custodian-held test-set proof for validation,
public-view generation and export. No v1 manifest may be silently upgraded; restart a not-yet-executed custody
workflow after authorised rulings are available. This protects integrity, not the identity of an operator.

## Intended use

Once the decisions above are made: internal evaluation (and, if permitted, training on development families) of
tool-call classifiers. Until then the candidate pool is for dataset construction and validation only. Test-family
identities, inputs, ids and seeds must never reach model developers or public artifacts.

## Privacy boundaries

- Candidate declarations, records, the id map, seeds and reports live only in `eval/sou35/private/`, which
  `eval/sou35/.gitignore` excludes; the pool tool refuses any output path git does not ignore.
- `eval/sou35/tests/test_release_privacy.py` searches every git-publishable file under `eval/sou35` and
  `docs/benchmarks/sou35` for private tokens (family ids, identities, descriptions, long argument strings, case ids,
  seeds) and never prints a matched token.

Validation: [VALIDATION.md](VALIDATION.md). Source: [`eval/sou35`](../../../eval/sou35/README.md).
