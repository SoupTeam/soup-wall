# SOU-35 validation instructions

From the repository root. Tested with Python 3.12.10 on Windows 11; other versions are untested.

```sh
python -m pip install -r eval/sou13/requirements-cp2.txt   # jsonschema==4.25.1 (shared with SOU-13)
```

## Public checkout (no private data)

```sh
python eval/sou35/run_tests.py          # toy families only; the private-pool privacy scan skips with a named reason
python eval/sou13/run_tests.py          # frozen SOU-13 suites must be unaffected
git diff --stat -- eval/sou13           # must be empty: SOU-35 never edits SOU-13 files
```

`run_tests.py` exits 1 on any failure, error, or skip other than `PRIVATE ARTIFACT MISSING`.

## Owner checkout (private candidate pool present)

```sh
python eval/sou35/run_tests.py --require-private     # any skip fails; the privacy scan must run
cd eval/sou35
python -m sou35.check_pool --pool private/pool --out private   # optional --pattern T/V/C/S (owner-only)
```

`check_pool` writes only below the ignored `private/` directory and exits 1 unless the intra-pool, novelty and
record-validation error counts are all 0. Its output is **owner-only** (see the dataset card): do not paste it into
issues, PRs or chat channels.

## Custodian workflow (not yet run on the candidate pool)

Run by the assigned sealed-test custodian only, in an ignored workspace. Every command first re-validates the pool
and records; a refusal exits 1 and prints only an error category.

```sh
cd eval/sou35
R="--workspace sealed/<name> --pool private/pool --records private/records/candidates.jsonl --rulings sealed/<name>/rulings.json --test-exclusions private/<policy>.json"
python -m sou35.release declare $R --custodian <name> --counts T/V/C/S      # full coverage requirements by default
python -m sou35.release commit  $R                                          # seed stays in the workspace
python -m sou35.release draw    $R --confirm
python -m sou35.release accept  $R --custodian <name> --accepted-at <time> --decision-ref <external record>
python -m sou35.release build-manifest $R --salt <salt>
python -m sou35.release freeze  $R --approved-by <name> --approved-at <time> --decision-ref <external record> --confirm
python -m sou35.release validate-manifest $R
python -m sou35.release public-view $R                                      # writes manifest.public.json
python -m sou35.release export  $R --authorization <auth.json> --generation-provenance private/<provenance.json> [--id-map private/ids/id_map.json] --out private/<dir>
```

The mandatory private `--test-exclusions` policy must match the exact-SHA reviewed supplement and current pool; an absent, incomplete or modified restriction list is refused before `declare`/`commit`. The source supplement must remain accessible to the custodian. The low-level `custody.commit`/`custody.draw` APIs require explicit group exclusions; `()` is appropriate only for artificial tests or genuinely unrestricted policies. **Do not run this example on v3 until the team authorizes custody operations.**

The export authorization file needs `scope: sou35_internal_dev_export`, `authorized_by`, `authorized_at`,
`decision_ref` and the frozen manifest's `manifest_sha256` and `rulings_sha256`. These fields are recorded, not authenticated (see the
dataset card).


**New v2 precondition:** The private `--rulings` register must be prepared from externally authorised human
semantic decisions and reviewed-case evidence before `commit`. Its shape is validated by `sou35.rulings`:
`version: sou35-semantic-rulings-v1`, `scope: sou35_synthetic_candidate_pool`,
`pool_digest`, `decisions` (question_id/status/reviewed_by/reviewed_at/decision_ref) and
`reviewed_cases` (id/row_sha256/status/reviewed_by/reviewed_at/decision_ref).
Decisions and case reviews marked `accepted` must have real externally retrievable review references.
The custodian holds this register privately; **never use the artificial toy approvals for the real pool**.
These fields are recorded, not authenticated. No real freeze/export/draw has been performed.
Unapproved records are excluded from development export entirely, including their labels.

**v2 case ledger (required for primary scoring).** A v1 register (above) is preserved and still validates, but it
records no evidence basis, so no case is primary under it and no split coverage can be met from it. A v2 register has
`version: sou35-semantic-rulings-v2`, `eligibility_policy: sou35-strata-v1`, `pool_digest` and the
`record_inventory_sha256` of the exact records. Decisions add `reviewer_kind: human` and a `reviewed_at` that must
parse as a real ISO-8601 date-time with an explicit offset (for example `2026-10-16T01:00:00Z`). Each
`reviewed_cases` entry has `id`, a `row_sha256` that must equal the digest of that exact record (checked for every
entry, pending included) and `status` (`accepted`, `pending`, `rejected`, `disputed`); non-pending entries need a human `reviewed_by`, `reviewer_kind: human`, `reviewed_at` and an
externally retrievable `decision_ref`; accepted entries also need `independent_of_generation: true`,
`questions_considered` covering the record's open questions and, for classification rows only, `evidence_basis`
(`interface_supported`, `program_only` or `information_limited`). `ai_technical_review_refs` may be listed but never
count as review. Entries are transcribed from genuine human decisions only: never migrate a pending v1 decision to
accepted and never invent a case-review reference. Strata and the hidden-default safeguard are described in
`eval/sou35/README.md`. Strata are computed only from a validated, immutable `rulings.Ledger` (`rulings.load`): the
manifest, feasibility, export and CLI paths validate the complete register once against the pool and the exact
record inventory, and the stratum-level APIs refuse a raw register.

**Generation provenance (export only).** The export requires a private file recording the ORIGINAL generation:
`provenance_version: sou35-generation-provenance-v1` and `original_generation` with `generator_version` (must equal
the records' `source_material.generator`), full `source_commit`, `command`, `generated_at`, `recorded_by`,
`pool_digest`, `record_inventory_sha256` and optionally `id_map_sha256`. The owner records it from the historical
generation; it is never derived from the current `HEAD`. The export stores the current tooling commit separately as
`export_tooling`. Records are not regenerated for this purpose.

*Limits.* The checks bind the declared provenance to the current pool, the exact record inventory and the records'
generator version. They **cannot** prove that the declared `source_commit` or `command` is the one that actually
produced the records: both remain owner attestations (the export manifest says so in
`generation_provenance_limits`). The current `HEAD` is neither compared with nor substituted for the original
revision.

*Id map.* If `id_map_sha256` is declared, the export requires `--id-map` with the private id-map file (read only by
the owner, at run time, from an ignored path). The export refuses unless the file's bytes have exactly that SHA-256,
it parses as JSON, every current case key (`family|kind|index`) maps to its record id, and no other key claims a
current id (keys of retired cases in the append-only map are tolerated). Only then is `id_map_verified: true`; with no
declared digest the export records `id_map_verified: false` and claims nothing about the id map. Digest syntax alone
is never treated as verification.

**Feasibility counts.** Three kinds of figure must not be confused:

| Kind | Source | Status |
| --- | --- | --- |
| Historical unfiltered calculation | `check_pool`, or `feasibility.report` without a ledger (`evidence_policy: raw_unfiltered_historical`) | no review filter; an upper bound only |
| Team Lead-conditional planning count | earlier owner-side planning under the scoped rulings and the closed-test restrictions, made before case-level evidence bases existed; not produced by any public code path and not published | planning input only |
| Approved feasibility | `feasibility.report` with a validated v2 ledger (`evidence_policy: sou35-strata-v1` plus `rulings_sha256`); only `primary` and `technical_error` strata count | the only figure valid under the v2 evidence policy |

Neither of the first two is approved feasibility. It must be recomputed owner-only once a genuine v2 ledger exists;
with no accepted v2 case review, no allocation is feasible. Requirements are never relaxed.

**Upgrade note:** The v1 manifest was never frozen for the real candidate pool; the new v2 manifest and
custody state are incompatible with v1. Do not reuse an earlier draw or infer an accepted semantic ruling.

Isolation checks before any PR:

```sh
git status --short --untracked-files=all             # no path under eval/sou35/private/ may appear
git check-ignore -v eval/sou35/private/pool/x.json eval/sou35/private/records/candidates.jsonl
test ! -e eval/sou13/cp2_sealed && echo "consumed SOU-13 sealed material absent"
```

## Earlier baseline results before v2 safeguards (2026-10-15, branch `feat/sou35-fresh-dataset`, base `e6f6305`)

| Where / command | Result |
| --- | --- |
| Isolated public checkout (`HEAD` files + the SOU-35 files only, no `private/`): `run_tests.py` | 82 ran, 81 passed, 1 skipped (`PRIVATE ARTIFACT MISSING`): PASS |
| Isolated public checkout: `run_tests.py --require-private` | FAIL, as intended (the private pool is required) |
| Isolated public checkout: `eval/sou13/run_tests.py` | CP1 74 ran / 54 passed / 20 skipped; CP2 371 / 240 / 131; PASS |
| Owner checkout: `run_tests.py --require-private` | 82 ran, 82 passed, 0 skipped: PASS |
| Owner checkout: `check_pool` (last run earlier on 2026-10-15; the pool has not changed since) | error counts 0 / 0 / 0 (intra-pool, novelty, record validation) |
| Owner checkout: `git diff --stat -- eval/sou13` | empty |

The SOU-13 skips are its own private artifacts, which are absent from both checkouts.

Privacy-gate control (isolated checkout, synthetic canary pool): clean files PASS; a canary planted as a comment in
a source file FAILS naming only the file, and the canary is not printed. Limits: exact substrings only; argument
strings under 12 characters are not scanned; only `eval/sou35` and `docs/benchmarks/sou35` are scanned; PR text,
commit messages and Linear are not covered; it runs only where the private pool exists; and a leak that makes a
Python file unparseable can be echoed by the interpreter's own traceback.

The baseline counts above apply to commit `0023729`, not to the v2 patch. Run the complete SOU-35
and SOU-13 test suites locally after applying the patch and replace these results only when verified.
