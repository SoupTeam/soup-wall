# SOU-35 source (draft, not released)

Tooling for a fresh, family-held-out synthetic tool-call dataset under the SOU-10 v0.4 contract
(`contract/updated_contract2.md`). **This folder contains no dataset.** It holds code, schemas and three clearly
artificial toy families (`tests/toy/`, `artificial_toy: true`) that exist only to test the pipeline.

| Path | Content |
| --- | --- |
| `sou35/guard.py` | Refuses to run if the consumed SOU-13 sealed directory is present (existence check only) |
| `sou35/adapters.py` | Import-only adapters onto the frozen SOU-13 CP2 interpreter, labels, identity and leakage code |
| `sou35/families.py` | JSON family declarations: schema, program, argument and class checks |
| `sou35/generate.py` | Declaration to records; labels mechanically derived from the audited execution |
| `sou35/records.py` | Record validator: everything is recomputed, nothing stored is trusted |
| `sou35/feasibility.py` | Split feasibility over leakage groups; reports impossible requirements, counts only |
| `sou35/custody.py` | Sealed-test custody: declare, commit, draw (commit-reveal), custodian acceptance; public states carry no seed or family id |
| `sou35/manifest.py` | Versioned family-disjoint manifest: deterministic draft, validation, freeze with an approval record, public view |
| `sou35/export.py` | Development export: excludes all unreviewed cases; requires frozen v2 manifest, test proof and explicit authorisation |
| `sou35/rulings.py` | Pool-bound, private semantic and case-evidence review decisions (recorded, not authenticated) |
| `sou35/release.py` | Thin custodian CLI over custody, manifest and export (see `docs/benchmarks/sou35/VALIDATION.md`) |

The custodian CLI requires a private `--test-exclusions` policy cross-checked against its exact-SHA reviewer supplement. It applies the bans before future test commitment and draw; the low-level custody API also requires the ban parameter explicitly. No real v3 draw, freeze, scoring or export is authorised by this documentation.

Approver, custodian and authorizer fields are recorded text bound into sha256 digests; they do not authenticate a
person and nothing is signed. The full manifest names test families and stays with the sealed-test custodian.

| `schema/` | `sou35_case.schema.json` (CP2 label contract reused verbatim), `sou35_family.schema.json` |

```sh
python eval/sou35/run_tests.py
# private candidate pool (declarations under the ignored private/ workspace); owner-only aggregates
cd eval/sou35 && python -m sou35.check_pool --pool private/pool --out private   # optional --pattern T/V/C/S: owner-only
```

`check_pool` writes records, the opaque id map and a family-level report only below `private/` or `sealed/`, and
only after `git check-ignore` confirms the path is ignored. Pool membership (development vs test) stays
`candidate_undetermined` until custody and split decisions are made by the responsible humans.

## Boundaries

- Nothing under `eval/sou13/` is modified; SOU-13 modules are imported read-only.
- Real family declarations, the candidate pool, id maps, seeds and generated records belong in the gitignored
  `private/` workspace and are never committed. Test-family identities are never published.
- Labels are **mechanical synthetic evidence** (re-executed program, typed access audit). They are not human
  approved, are never called Gold, and inherit no SOU-13 reviewer decision. The schema has no `confirmed` status
  and requires `human_semantic_approval: null`. Release tooling now also requires an external-decision
  register with exact per-case review digests; this is not a Gold declaration or a human signature.

## Pending human decisions

| Id | Decision needed |
| --- | --- |
| Q-S35-DECL-EVIDENCE | Whether closed-program `false` labels are acceptable for SOU-35 (the SOU-13 ruling was scoped to its 179 cases) |
| Q-S35-INTERNAL-ACCESS | Whether internal ACL reads / key enumeration inside an ACL change or prefix delete are not `read` |
| Q-S35-EMPTY-BATCH | Whether an empty batch is a proven no-op |
| Q-S35-UNMODELLED-MODE | Whether an unlisted mode value is full unknown |
| Q-S35-OPTIONAL-DEFAULT | Whether an absent optional flag takes the declared default branch |
| Q-S35-HUMAN-REVIEW | Independent human semantic reviewer (not assigned) |
| Q-S35-DATA-USE | SOU-35 data-use permission (not granted; no license is assumed) |
| (custody) | Owner assigned as sealed-test custodian by team lead on 2026-10-15 |
