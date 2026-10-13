# SOU-13 private full validation (owner only)

This procedure validates the published SOU-13 source against the frozen CP1/CP2 artifacts, including the
custodian-only material. **Only the dataset owner runs it, on the owner workstation.** Never run it in CI, a
shared workspace or a coding-agent session. Never place its working copy inside a Git checkout.

Publish only the aggregate ledger (`result`, counts, skip reasons). The test log can contain case ids,
family ids or label values in assertion messages, so it stays private.

Technical validation confirms no label. The 179 CP2 development cases have independent semantic sign-off and a
separately approved private Gold Addendum v1 plus internal-use-only export authorization; source freezes are
unchanged. Public dataset licensing/publication remains unapproved
([acceptance status](ACCEPTANCE.md)).

## Prerequisites

- Windows PowerShell and Python **3.12.10**, the version recorded in the CP1 freeze, with `jsonschema==4.25.1`
  (`eval/sou13/requirements-cp2.txt`).
- `ssh-keygen` with `-Y sign` support (OpenSSH 8.1 or later), used by the trust-anchor tests.
- The private tree (`<private-root>`): `data/`, `review/`, `docs/`, `cp2/`, `cp2_sealed/` and `handoff/`.
- The archived v0.2 pilot data folder for the v0.2 leakage analysis. It must be the historical v0.2 data
  directory that directly contains `pilot_candidates.jsonl`. Without it, or with a wrong path, the strict run
  reports one error and must be recorded as incomplete.
- The **owner trust anchor** for the frozen split manifest, kept outside every repository:
  - the signed anchor document and its `.sig` signature;
  - an `allowed_signers` file;
  - the independently pinned owner key fingerprint;
  - the signer identity.

  The validator refuses a FROZEN manifest without it (audit F2). Without the anchor, the strict run errors
  on the anchor-dependent tests.

## 1. Fix the inputs

```powershell
$Repo    = 'D:\soup-wall-sou13'                  # checkout under review
$Private = '<private-root>'                       # frozen owner tree; never modified by this procedure
$V02     = '<historical v0.2 data directory containing pilot_candidates.jsonl>'
$Stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$Work    = Join-Path $env:TEMP "sou13-private-$Stamp"          # disposable; outside every Git checkout
$Out     = Join-Path $env:USERPROFILE "sou13-validation-$Stamp" # retained results, private
New-Item -ItemType Directory -Force $Out | Out-Null
git -C $Repo rev-parse HEAD                      | Set-Content "$Out\source-commit.txt"
git -C $Repo status --short                      | Set-Content "$Out\source-status.txt"
python --version
```

Record whether the working tree has uncommitted changes. A ledger refers to the exact source that was tested.

## 2. Verify source identity (digests only)

```powershell
python "$Repo\eval\sou13\scripts_cp2\verify_source_identity.py" `
    --freeze "$Private\data\freeze.json" `
    --dev-manifest "$Private\handoff\dev_review_package\MANIFEST.json" `
    --private-root $Private | Tee-Object "$Out\identity.json"
```

**Stop unless `result` is `PASS`.** A pass means three things:
- the 10 CP1 frozen source digests match;
- the 6 dev-package pins match;
- every source module and schema is byte-identical to the private tree.

The only `repo_only` files may be the new public files.

## 3. Build the disposable working copy

```powershell
New-Item -ItemType Directory $Work | Out-Null
git -C $Work rev-parse 2>$null; if ($?) { throw 'working copy is inside a Git checkout' }
robocopy $Private $Work /E /XD __pycache__ .git /NFL /NDL /NJH /NJS | Out-Null
Remove-Item "$Work\tests", "$Work\tests_cp2" -Recurse -Force -ErrorAction SilentlyContinue
robocopy "$Repo\eval\sou13" $Work /E /XD __pycache__ /NFL /NDL /NJH /NJS | Out-Null
```

The second copy adds the repository's tests, `_testsupport.py`, `run_tests.py`, `sou13gold/` and the new
scripts. Step 2 proved the overwritten source modules identical. The private tree itself is never modified.
The working copy contains custodian-only material. It stays on this workstation and is deleted in step 6.

## 4. Run the strict suite

```powershell
$env:SOU13_V02_DATA             = $V02
$env:SOU13_CP2_ANCHOR           = '<anchor.json outside every repository>'   # signature: <anchor.json>.sig
$env:SOU13_CP2_ALLOWED_SIGNERS  = '<allowed_signers file>'
$env:SOU13_CP2_TRUSTED_KEY_FPR  = '<pinned owner key fingerprint, SHA256:...>'
$env:SOU13_CP2_SIGNER           = '<signer identity>'
$env:SOU13_CP2_ANCHOR_ATTEMPT_LOG = "$Out\anchor-attempts.jsonl"           # outside the working copy
python "$Work\run_tests.py" --require-private 1> "$Out\ledger.json" 2> "$Out\test-log.private.txt"
'SOU13_V02_DATA', 'SOU13_CP2_ANCHOR', 'SOU13_CP2_ALLOWED_SIGNERS', 'SOU13_CP2_TRUSTED_KEY_FPR',
    'SOU13_CP2_SIGNER', 'SOU13_CP2_ANCHOR_ATTEMPT_LOG' | ForEach-Object { Remove-Item "Env:\$_" }
Get-Content "$Out\ledger.json"
```

`--require-private` disables every private-artifact skip, so a missing artifact is an error. At this
revision, the expected result is:

- `ran` **445**, `failed` 0, `errored` 0, `result` `PASS` in the final owner-reported current-source run.
  The owner-reported Windows ledger has 441 passed and 4 expected skips. This includes:
  - the 93 data-free gold-export tests (`tests_cp2/test_gold_export.py`, `tests_cp2/test_gold_review_queue.py`,
    `tests_cp2/test_gold_batch.py`), which also run in the public suite;
  - the privacy-gate symlink regression added at the merge of PR #80.

  Commit `bdd1f92` had 343 tests; see Recorded runs;
- `skipped` exactly **3**, all public-copy counterpart tests, which skip by design when restricted material is
  present:
  - `test_splits.PublicCopyAssignment` (2 tests);
  - `test_taxonomy.TaxonomyIsValid.test_public_copy_is_the_documented_development_subset`.

  On Windows without the symlink privilege (Developer Mode or an elevated shell), one more test skips:
  `test_release_privacy_gate.PathAndContentRules.test_dangling_symlink_is_not_treated_as_a_deletion`, with
  reason `symlink creation unavailable`. That makes 4 skips. Record the reason; no other additional skip is
  acceptable.

Any other skip, failure or error is a finding. Investigate it without editing frozen data. Report it with its
test name, not its data.

Watch two tests in particular:

| Test | Why |
| --- | --- |
| `test_freeze.FreezeIsExplicit.test_repository_manifest_is_frozen_valid_and_authoritative` | It checks that the persisted full manifest is FROZEN, carries a complete freeze record and is valid. It replaced a pre-freeze assertion that the manifest is DRAFT. |
| `test_cp1_compat.Cp2Pipeline.test_frozen_manifest_without_owner_anchor_fails` | It is a negative control: without the owner anchor, validating the frozen manifest must fail. |
| `test_review_integration.ReviewIntegration.test_only_the_dev09_family_changed_in_the_draft_manifest` | It asserts that the historical DEV-09 family id is absent from the full 45-family manifest. This is the private evidence for the provenance exception (step 5). |

## 5. Check the recorded provenance exception

The privacy gate allows exactly one family id outside the public taxonomy that is not a synthetic test
fixture. It is the historical DEV-09 family id, and it is allowed only in
`tests_cp2/test_review_integration.py`. The owner confirmed it on 2026-10-11 from the dev-only
`CP2_REVIEW_INTEGRATION.md`. It was verified absent from the frozen public split view, where its replacement
`fam.unknown.workspace_tidy` is in train.

The only remaining private evidence is the full-manifest assertion in step 4:
`test_only_the_dev09_family_changed_in_the_draft_manifest` must pass. If it fails, the exception is wrong.
Remove the id from the test and the registry before publication. No separate search of sealed files is
needed.

## 6. Clean up and check for leaks

```powershell
Remove-Item $Work -Recurse -Force
Test-Path $Work                                   # must be False
git -C $Repo status --short --ignored -- eval/sou13
python "$Repo\eval\sou13\scripts_cp2\check_release_privacy.py" --git $Repo `
    --deny-digests "$Private\data\freeze.json" "$Private\handoff\dev_review_package\MANIFEST.json"
```

`git status` must show no new ignored or untracked artifact under `eval/sou13`. The gate must pass. It reads
the denylist files as digests only.

## 7. Record

Keep `identity.json`, `ledger.json`, `source-commit.txt` and `source-status.txt` in `$Out`. The PR may
quote:
- the source commit;
- the identity result;
- the ledger counts and skip reasons;
- the result of the step 5 check.

Keep `test-log.private.txt` private.

## Recorded runs

These are owner-reported aggregate results. The private ledgers and logs are not in this repository and were
not inspected here.

| Run | Result | Notes |
| --- | --- | --- |
| 1 (owner) | **FAIL**: 340 ran / 324 passed / 10 failed / 3 errored / 3 skipped | Causes: test fixtures that assumed a DRAFT manifest after the freeze, a test-name shadowing defect, and missing owner trust-anchor configuration. All three are fixed in this revision. |
| 2 (owner-reported, 2026-10-12) | **PASS**: 343 ran / 340 passed / 0 failed / 0 errored / 3 skipped | CP1 74 passed; CP2 266 passed and 3 skipped. Source identity PASS (46 byte-identical files); freeze anchor signature verified against the pinned fingerprint; privacy gate PASS; disposable working copy deleted. Run after correcting `SOU13_V02_DATA` to the historical v0.2 data directory. No frozen data or signed manifest was modified. |
| 3 (owner-reported, final for PR #80) | **PASS**: 343 ran / 340 passed / 0 failed / 0 errored / 3 skipped | Source commit `bdd1f92`. The 3 skips are the expected public-copy counterparts listed in step 4. This run covers the test-only change to `test_obsolete_contract_binding_rejected` (a visibly synthetic obsolete-contract digest with two added assertions) that run 2 predated. |

| 4 (owner-reported, 2026-10-12 final current-source CP2 release) | **PASS**: 445 ran / 441 passed / 0 failed / 0 errored / 4 skipped | Three named public-copy counterpart skips and one expected Windows symlink-privilege skip. The private ledger remains owner-held and was not inspected in the public repository; see [SOU-13](https://linear.app/soup-wall/issue/SOU-13) for the owner's result. |

Runs 2 and 3 are historical evidence for earlier revisions. Run 4 is the owner-reported current-source release
ledger; future source revisions still require their own strict run.

## 8. Diagnostics to share after a failing run

Share only the summary produced below. Do not share the log itself or any data, path, message, digest or anchor
value. The extractor prints only, for each failing or erroring test:
- the outcome;
- the test id;
- the exception class;
- the `file.py:line(function)` frames.

It omits every message. It runs inline because a saved `.ps1` file may be blocked by the execution policy.

```powershell
$blocks = (Get-Content -Raw "$Out\test-log.private.txt") -split '(?m)^={50,}\r?\n'
$summary = foreach ($b in $blocks) {
    $head = [regex]::Match($b, '^(FAIL|ERROR): (\S+) \(([^)]+)\)'); if (-not $head.Success) { continue }
    $frames = [regex]::Matches($b, 'File "[^"]*[\\/](?<f>[A-Za-z0-9_]+\.py)", line (?<n>\d+), in (?<fn>[A-Za-z0-9_<>]+)') |
        ForEach-Object { "$($_.Groups['f'].Value):$($_.Groups['n'].Value)($($_.Groups['fn'].Value))" }
    $exc = [regex]::Matches($b, '(?m)^(?<c>[A-Za-z_][A-Za-z0-9_.]*(Error|Exception|Exit|Interrupt|Warning))\b') |
        Select-Object -Last 1
    '{0} | {1} | {2} | {3}' -f $head.Groups[1].Value, $head.Groups[3].Value, $exc.Groups['c'].Value, ($frames -join ' > ')
}
$summary | Set-Content "$Out\failure-summary.txt"
$summary
```

Review `failure-summary.txt` before sharing it: it should contain only test names, class names and line
numbers.

Checklist for the failures reported on 2026-10-11:

| Test | Needed | What it distinguishes |
| --- | --- | --- |
| `test_public_mode.AdversarialAudit.test_public_copy_reveals_nothing` | the `test_public_mode.py` line of the failing assertion (23–32). If it is line 29, also the **number** of strong-fingerprint hits, without their keys. | Line 30 is the public-copy validator result; it needs the anchor variables. Lines 23–29 would be a leakage finding and block release. |
| `test_candidates.SealingOnDisk.*` (all three) | outcome, exception class and `test_candidates.py` line | Two errors were `TypeError` at lines 158 and 173 (name shadowing, now fixed). Any remaining error is new. |
| every other failure | outcome, exception class and frames | — |
