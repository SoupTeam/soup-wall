# Result-inspection two-revision comparison (SOU-191)

This tool compares two recorded offline runs of the frozen public SOU-123 result-inspection corpus
([corpus guide](../operations/RESULT_INSPECTION_CORPUS.md)) made with two accepted-main revisions. It reports how attack
misses and benign false refusals changed between them. It is a separate detector-observation contract. It is not
AgentDojo matched/1 ([paired regression](paired-regression.md)) and does not measure task completion or utility.
Allow, Ask, Deny and Escalate are what one detector call returned. They are not evidence of attack prevention,
zero execution, readiness or live-model behaviour.

## Components

| File | Role |
| --- | --- |
| [predeclaration.json](evidence/sou191/predeclaration.json) | Revisions, corpus, policy, build command, outcome contract, grouping and attempt rule, committed before measurement |
| [result_inspection_record.py](../../scripts/benchmarks/result_inspection_record.py) | Controlled build and run of one predeclared revision; writes a new `attempt-NNN` |
| [result_inspection_compare.py](../../scripts/benchmarks/result_inspection_compare.py) | Offline verification and comparison; reuses SOU-153 strict reading and uncertainty helpers |
| [result_inspection_controls.py](../../scripts/benchmarks/result_inspection_controls.py) | Negative controls on temporary mutated copies of the retained runs |

## Recording

Prerequisites: Git, Python 3.10+, rustup with toolchain 1.99.1 and the Windows x86_64 MSVC native build environment
described in the [development guide](../DEVELOPMENT.md#prerequisites). Use a scratch directory outside the repository
for `--work-root`.

```powershell
python scripts/benchmarks/result_inspection_record.py --role baseline `
  --predeclaration docs/benchmarks/evidence/sou191/predeclaration.json `
  --work-root $env:TEMP\sou191-work --out docs/benchmarks/evidence/sou191/runs/baseline
python scripts/benchmarks/result_inspection_record.py --role candidate `
  --predeclaration docs/benchmarks/evidence/sou191/predeclaration.json `
  --work-root $env:TEMP\sou191-work --out docs/benchmarks/evidence/sou191/runs/candidate
```

For each attempt the recorder does the following:
- requires the full commit on the first-parent history of the predeclared accepted-main ref;
- clones it with `core.autocrlf=false`, and requires a clean tree with every build input and payload byte-identical
  to its Git object, both before and after the build;
- refuses Cargo configuration files and build-affecting variables (`RUSTFLAGS`, `RUSTC*`, `RUSTUP_TOOLCHAIN`,
  `CARGO_TARGET_*`, `CARGO_BUILD_*`, `CARGO_PROFILE_*`, `CARGO_INCREMENTAL`);
- builds with the predeclared command into a new `CARGO_TARGET_DIR`;
- takes the executable only from Cargo's `compiler-artifact` message inside that directory;
- hashes the executable before and after running it on the checkout's own corpus and policy.

The recorder keeps the raw adapter output, the exit status and timeout flag, and the bounded build and run logs.
Local paths in the logs are replaced with `<work>`, `<repo>` and `<home>`. It also keeps the original
`sw-result-inspection-report/1`, built by that revision's own `run_corpus.build_report`.

Attempts are never overwritten. The first attempt that executes the adapter is the measurement for its role. A
failed execution stays the measurement, and later attempts are listed but not used.

## Comparison and reproduction

```powershell
python scripts/benchmarks/result_inspection_compare.py `
  --predeclaration docs/benchmarks/evidence/sou191/predeclaration.json `
  --baseline docs/benchmarks/evidence/sou191/runs/baseline `
  --candidate docs/benchmarks/evidence/sou191/runs/candidate `
  --out-dir $env:TEMP\sou191-compare --expect docs/benchmarks/evidence/sou191/comparison
```

The command writes `comparison.json` (`soup-wall-result-inspection-comparison/1`), `units.csv` and `report.md`.
`--expect` checks that the retained outputs are reproduced byte for byte from the retained inputs. Reproduction
re-verifies the recorded runs and does not rerun the detector. A fresh recording measures new latencies, so its
latency values are not expected to match.

Exit status: 0 comparable, 1 non-comparable (toolchain, command, environment or Cargo configuration differs), 2
invalid input, 3 usage error.

The following inputs are refused:
- changed, missing, duplicate or fabricated cases;
- payload, manifest or policy drift;
- a commit that is not on accepted main;
- a tree or build-input blob that differs from Git;
- an unclean checkout;
- an executed artifact that differs from the built one;
- malformed, non-finite, truncated or oversized data;
- fields outside the adapter's per-status result contract;
- a report that cannot be rebuilt byte for byte from the raw output, which catches edited totals or edited
  acceptance;
- missing retained files or digests.

## Outcome contract

The outcome contract is `soup-wall-result-inspection-outcomes/1`, defined in `OUTCOME_CONTRACT` and `DENOMINATORS`.

- Semantic cases are *inspected*, *incomplete* (budget refusal), *error* (adapter technical error) or *unknown*.
  Technical cases are reported only by status.
- Rule CI-1: a result whose rule starts with `mcp_result_evidence_incomplete_` is *incomplete* on either side, never
  a caught attack. The candidate adapter already reports such results as `evidence_budget_not_inspected`. The
  baseline engine (68d8a597) has no evidence-budget refusal path, and that rule name first appears in 5228ddd2. The
  original report and raw output are kept unchanged, and each case also shows its original report outcome.
- The adapter writes all results once, at exit. After a timeout or a non-zero exit, every planned case is
  *unobserved* and `attempted` and `not_run` are null. The tool does not infer partial progress.
- Rates use the inspected cases only. Missing-outcome bounds cover the planned set. Attack
  `caught_instruction->missed_instruction` and benign `benign_allowed->false_refusal` transitions are reported
  separately, together with the verdict-level transitions. They are never merged into one direction.
- Latency is the microseconds of one `preview_native_result` call, as measured inside the adapter. It is
  descriptive only, with counts of measured, unmeasured and timeout-censored cases.

## Uncertainty

The predeclared resampling units follow the SOU-153 rule: dependency clusters merged with semantic families. They
were derived without any outcome from the corpus generator and the frozen manifest. The dependencies are:
- the two cases of a pair;
- shared host-file templates;
- the companion files shared by every `read_multiple_files` payload;
- identical directive text.

The families are the frozen categories. The result is 2 units for 48 semantic cases, far below the SOU-153 minimum
of 10 effective clusters. Every interval is therefore reported as `insufficient_clusters` and no change is stated as
established. The paired transitions remain descriptive. No other grouping is computed.

## Trust boundary

The verifier checks these against Git objects and retained bytes:
- the commits, trees and build-input blobs;
- the corpus and policy bytes;
- the raw-output digests;
- the derivation of each report from its raw output.

The link from source to binary is an attestation of the recording machine: Cargo's artifact message, the fresh
target directory, the checkout checks, and the artifact hash before and after execution. The record has no
signature. A malicious recording machine, a modified toolchain, or a consistently fabricated run directory cannot be
detected offline. Debug MSVC builds are not expected to be bit-reproducible.
