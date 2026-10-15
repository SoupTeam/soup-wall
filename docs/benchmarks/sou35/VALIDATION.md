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
R="--workspace sealed/<name> --pool private/pool --records private/records/candidates.jsonl"
python -m sou35.release declare $R --custodian <name> --counts T/V/C/S      # full coverage requirements by default
python -m sou35.release commit  $R                                          # seed stays in the workspace
python -m sou35.release draw    $R --confirm
python -m sou35.release accept  $R --custodian <name> --accepted-at <time> --decision-ref <external record>
python -m sou35.release build-manifest $R --salt <salt>
python -m sou35.release freeze  $R --approved-by <name> --approved-at <time> --decision-ref <external record> --confirm
python -m sou35.release validate-manifest $R
python -m sou35.release public-view $R                                      # writes manifest.public.json
python -m sou35.release export  $R --authorization <auth.json> --out private/<dir>
```

The export authorization file needs `scope: sou35_internal_dev_export`, `authorized_by`, `authorized_at`,
`decision_ref` and the frozen manifest's `manifest_sha256`. These fields are recorded, not authenticated (see the
dataset card).

Isolation checks before any PR:

```sh
git status --short --untracked-files=all             # no path under eval/sou35/private/ may appear
git check-ignore -v eval/sou35/private/pool/x.json eval/sou35/private/records/candidates.jsonl
test ! -e eval/sou13/cp2_sealed && echo "consumed SOU-13 sealed material absent"
```

## Recorded results (2026-10-15, branch `feat/sou35-fresh-dataset`, base `e6f6305`)

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
