# SOU-129 current evidence reconciliation

Selected accepted main: `adefce2a658272e5f23c9c72ef791befe0285648`.
Final accepted reporter SHA: **not available; Draft review required**.

- [Exact selected inputs](selection.json)
- [Machine-readable dossier and blocker ledger](current-dossier/dossier.json)
- [Short English scorecard](current-dossier/scorecard.md)
- [Operator command and validation contract](../../PILOT_EVIDENCE_DOSSIER.md)
- [Unchanged SOU-106 original failed result](../sou106/measured-report.json)
- [Original two Ask blockers](../sou106/runtime-blockers.json)
- [Earlier attempt 1](../sou106/attempt-1.json) and [attempt 2](../sou106/attempt-2.json)
- [Original Ask component report](../sou-112/linux-qualification.json)
- [Original prepared-run component report](../sou-116/linux-prepared-run.json)

## Result

The command exits **1 / NOT_READY** with complete reporting output. This is an
expected, real reconciliation result, not a hidden failing test. No actual-host
run was performed by this command. The 10/12 benign failure with two interruptions,
8/8 refusal variants and zero forbidden effects at `ce4f76d` remains unchanged.
Historical component reports cannot qualify the different selected candidate;
environment and some identity bindings are absent or different. No green PR
badge is an input to the decision. The chosen expected asset hashes are the
explicit SOU-106 selection, not a claim of new candidate binary identities.

## Verification performed

Windows, Python 3.13.12; TEMP/TMP pointed at an owned writable temporary directory.

- `python -B -m unittest discover -s scripts/tests -p test_pilot_dossier.py -v`:
  **33/33 pass**, zero skips. Includes actual local Git commit/tree resolution,
  synthetic complete/incomplete records, hash corruption, missing files, stale
  and mixed source, incorrect policy/profile/registry/classifier identities,
  unknown schema, missing denominators, contradictory witnesses, malformed ZIP
  paths, symlinks, missing members, expansion bounds and member/archive hashes.
  The intentionally failed measurement returns exit 1 with its failure reason;
  invalid selection and output reuse return exit 2.
- `python -B -m unittest discover -s scripts/tests -p test_pilot_measurement.py -v`:
  existing **16/16 pass**, zero skips. The Windows hard-link regression needed
  permission outside the restricted execution sandbox; original tests unchanged.
- `python -B scripts/ci_components.py --check`: pass.
- `python -B -m unittest discover -s scripts/tests -p test_ci_components.py -v`:
  **8 of 9 methods pass**; the remaining method has two failing Bash subcases.
  `C:\WINDOWS\system32\bash.exe -c 'exit 0'` independently returned
  `Bash/E_ACCESSDENIED`. This is retained as an environment limitation; no test
  was disabled or relabeled and no WSL/toolchain was installed.

The focused dossier suite is added to the existing lightweight Draft job. Normal
CI discovery already includes it. No duplicate runtime matrix was dispatched;
CI admission and final integration remain TL work. Rust, Linux/WSL runtime,
provider, paid-model and private-data acceptance were not run or claimed here.

Regenerate into a **new** directory with the command in the operator guide.
Compare `selection_sha256`, `reporter_sha256`, `reporter_dependencies`, candidate,
evidence content hashes and ledger to this record. If integration changes the
candidate, retain this record and generate another; never replace the original
runtime evidence or copy its passing rows onto another commit.

## Subsequent scenario inventory correction

The reporter now requires 15 Ask and 11 prepared cases, matching the current
producers (`git/collector_term` and `host-crash`). The record above remains the
original `a54d1de0` reconciliation, not a current-schema runtime observation.
The updated focused suite passes 36/36, including missing/duplicate new cases
and absent cleanup witnesses. The old selected 14/10 reports correctly remain
non-qualifying under the new inventory; no historical JSON was edited.
