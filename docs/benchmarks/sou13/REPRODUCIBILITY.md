# SOU-13 reproduction, integrity and safe-release procedure

Technical reproducibility (this page) is separate from label approval, dataset licensing and release
authorization ([acceptance status](ACCEPTANCE.md)). Passing every check here confirms no label.

## Public data-free checks

Run from the repository root with Python 3.12 (validated with 3.12.10; 3.10 and 3.11 untested):

```sh
python -m pip install -r eval/sou13/requirements-cp2.txt
python eval/sou13/run_tests.py --expect-skipped 150
python eval/sou13/scripts_cp2/check_release_privacy.py --git .
```

`run_tests.py` prints an exact ledger: ran, passed, failed, errored and skipped, with every skip reason. It
fails on any failure or error, and with `--expect-skipped` it also fails when the skip count changes. A test
that newly starts skipping cannot pass unnoticed. Skips are limited to tests whose named private artifacts are
absent (`eval/sou13/_testsupport.py`).

`check_release_privacy.py --git` reads the content of every file a commit could contain: tracked changes,
staged and intent-to-add files, and untracked files that are not ignored. It fails closed on:
- restricted paths;
- raw data types;
- key markers;
- literal case IDs;
- owner absolute paths;
- label rows;
- family IDs outside the public taxonomy;
- unreadable files.

## Source identity with the frozen records

```sh
python eval/sou13/scripts_cp2/verify_source_identity.py \
    --freeze <private-root>/data/freeze.json \
    --dev-manifest <private-root>/handoff/dev_review_package/MANIFEST.json \
    --private-root <private-root>
```

This script reads digests only. It checks three things:
- The CP1 freeze source inventory: 10 LF-normalised source digests, with no file added to `sou13/*.py` or
  `scripts/*.py`.
- The CP2 development package pins: 6 raw-byte digests of the interpreter tools, schemas and requirements.
- Byte identity of every source module and schema with the owner tree.

`tests_cp2/test_freeze_inventory.py` repeats the first two checks without private input, using digests
copied from those records. `.gitattributes` keeps `eval/sou13/**` at LF so that raw-byte digests hold on every
platform.

The reference digests of the frozen logical split manifest and of the CP2 development handoff are held in the
owner's private records. Neither the artifacts nor their digests are published in this repository.

A self-hash checks consistency, not origin. Origin requires the owner-signed anchor verified against an
independently pinned ED25519 key fingerprint.

## Private full validation (owner only)

Follow [PRIVATE_VALIDATION.md](PRIVATE_VALIDATION.md). It covers the identity check, a disposable working
copy outside every Git checkout, the strict run (`--require-private`) with its expected ledger, the check of
the recorded family-id provenance exception, cleanup and the leak check.
Never run it in CI or in a shared or agent workspace.

Expected technical summary from the owner's private review reproduction:
- 179 candidates in 35 variants;
- 179 owner-rule-to-source agreements;
- frozen record statuses: 173 provisional, 6 pending, 0 confirmed.

The owner's rule decisions and the synthetic model share design assumptions, so this mechanical agreement is
**not** an independent accuracy test. Independent semantic approval is a separate record: the Independent Dev
Review Sign-off (2026-10-11) covers all 179 CP2 development cases. The frozen statuses change only through a
versioned gold release, which has not been issued.

## Freeze and custody

The sealed custodian package has passed technical verification:
- 54 records;
- 0 structural errors;
- self-consistency PASS;
- anchored integrity PASS.

Test custody was confirmed by an owner decision recorded on 2026-10-11. Label correctness is still
**NOT VERIFIED**; independent test-gold review is pending. Never publish its
archive, the test family identities, the test gold or the private signing key.

## Release integrity gates

- Record the source commit and the exact digest of any review addendum. Do not regenerate the original split.
- Run the privacy gate on the actual prospective commit, not on a scratch folder. Also pass the private
  digest records, which are read as digests only:

  ```sh
  python eval/sou13/scripts_cp2/check_release_privacy.py --git . \
      --deny-digests <private-root>/data/freeze.json <private-root>/handoff/dev_review_package/MANIFEST.json
  ```

- Run the private full validation against the version-matched immutable inputs.
- Record a provenance and license decision before any dataset export for model training. A gold development
  export is built only by `build_gold_dev_export.py`. It needs an export-grade addendum chain and an approved
  export authorization with license-owner and dataset-owner decisions ([gold development export](GOLD_DEV_EXPORT.md)).
- Require owner approval before opening or updating a public pull request. A draft public pull request is
  still public.
