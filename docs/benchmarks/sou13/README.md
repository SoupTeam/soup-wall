# SOU-13 family-held-out pilot (candidate integration)

**Status: candidate source integration. This is not a released dataset. The 179 CP2 development cases have
independent semantic sign-off, but no gold release has been issued.**

The SOU-13 Checkpoint 1 (CP1) and Checkpoint 2 (CP2) implementation, schemas, validators and tests live in
[`eval/sou13/`](../../../eval/sou13/README.md). The directory is self-contained: its own folder is the project
root for both frozen source inventories, so no SOU-13 file shares a glob with the repository's `scripts/`.

The repository does **not** contain the frozen CP1 records, CP2 development exports, review worksheets,
open-question registers, split manifests, signed anchors, the sealed test split or any custodian material.
Those artifacts remain in the owner's immutable, restricted workflow. Dataset publication and licensing are
pending approval.

## Contents

- **Taxonomy:** orthogonal `read`, `write`, `delete`, `send_data` and `change_permissions`, plus a Boolean
  `unknown`. A per-action `null` means "not established" and is masked; it is never scored as `false`.
- **CP2 evidence:** a tool or server identity selects a declarative synthetic program. An in-memory
  interpreter emits a typed-access trace and an audit. A clean synthetic trace is **not** independent proof of
  real MCP effects.
- **Frozen pilot accounting:** 252 cases in 45 families. Train 90, validation 54, calibration 54 and sealed
  test 54. The development subset is 19 legacy CP1 cases plus 179 CP2 cases. The nine sealed test families
  remain custodian-only.
- **Owner semantic review:** 35 variants cover the 179 development cases with mechanically consistent results.
  - 80 per-case inspections were attested by the owner.
  - 6 cases were reviewed as a family batch.
  - 93 cases were propagated from owner-approved rules, with a machine check per case.

- **Independent Dev Review Sign-off** (owner record, 2026-10-11): received for all 179 CP2 development cases,
  including the six Q-FUTURE cases and the agreed internal-read and keys-enumeration interpretations. It is a
  confirmed semantic approval, not a gold release. Q-CP2-DECL-EVIDENCE remains a separate open question.
- **Frozen CP2 development label statuses:** 173 provisional, 6 pending, 0 confirmed. These are the frozen
  records' statuses and change only through a versioned gold release.
- **Gold-label addenda (interface only):** future gold decisions must be issued as versioned, hash-chained
  addenda ([`schema/gold_addendum.schema.json`](../../../eval/sou13/schema/gold_addendum.schema.json),
  [`sou13gold/addendum.py`](../../../eval/sou13/sou13gold/addendum.py)). No addendum has been issued.

See the [review protocol](REVIEW_PROTOCOL.md), [dataset card](DATASET_CARD.md),
[reproduction and gates](REPRODUCIBILITY.md), [owner-only private validation](PRIVATE_VALIDATION.md) and
[acceptance status](ACCEPTANCE.md).

## Public checks (no private data)

Run from the repository root with Python 3.12 (validated with 3.12.10; 3.10 and 3.11 untested):

```sh
python -m pip install -r eval/sou13/requirements-cp2.txt
python eval/sou13/run_tests.py
python eval/sou13/scripts_cp2/check_release_privacy.py --git .
```

The public run executes every test whose inputs ship in the repository. Other tests are skipped with
`PRIVATE ARTIFACT MISSING:` followed by the exact paths they need.

The public run proves several things:
- source identity with both freezes;
- schema validity;
- the CP2 interpreter semantics, leakage-graph logic, near-duplicate logic and trust-anchor logic on synthetic
  inputs;
- the gold-addendum rules;
- the privacy gate.

It does **not** validate the frozen dataset. That requires the
[owner-only private procedure](PRIVATE_VALIDATION.md).

## Documented exceptions to repository conventions

The source modules under `eval/sou13/{sou13,sou13cp2,scripts,scripts_cp2}` are kept **byte-identical** to the
frozen owner tree, and `scripts_cp2/verify_source_identity.py` checks this. The identity is what lets a
private run validate exactly the published source.

- **License headers:** files under the CP1 freeze, files pinned by the CP2 dev package, and the other
  byte-identical modules have no SPDX header. They are covered by the repository's Apache-2.0
  [LICENSE](../../../LICENSE). Every new public-only file has a header. This license covers code only; the
  dataset license is pending.
- **Language:** the following files contain Russian review text or text emitted into private review packages:
  - CP1-frozen `sou13/build.py` and `sou13/cases.py`;
  - `sou13cp2/handoff.py`, `sou13cp2/generate.py` and `sou13cp2/revisions.py`.

  Translating them would change frozen hashes or the bytes of generated packages, so they are left unchanged.
  New documentation is in English.
- **Open-question registers:** `docs/OPEN_QUESTIONS.md` and `docs/CP2_OPEN_QUESTIONS.md` are referenced by the
  validators relative to `eval/sou13/`. They are owner-local documents and are not published here. Tests that
  need them are skipped in public mode and listed by name.
- **Overlay correction:** the integration overlay carried a superseded `schema/cp2_case.schema.json` that
  accepted 10-hex-digit case ids. The repository uses the copy pinned by the CP2 development package (`e6c55c…`),
  which matches the 128-bit identifiers issued by `sou13cp2/case_ids.py`.
