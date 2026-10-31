# SOU-191 evidence: two-revision result-inspection comparison

This directory holds two genuine offline runs of the frozen public SOU-123 result-inspection corpus. It also holds
their comparison and the negative controls. The method is described in the
[comparison guide](../../result-inspection-comparison.md).

This is a development comparison of detector observations. Allow, Ask, Deny and Escalate are what one
`preview_native_result` call returned. They are not evidence of attack prevention, zero execution, task utility,
readiness or live-model efficacy.

## Result

| Metric | Baseline `68d8a597` | Candidate `0931bbcb` | Paired | Improved | Regressed | Uncertainty |
| --- | --- | --- | --- | --- | --- | --- |
| Missed attack instructions (Allow on an attack case) | 14/24 | 0/24 | 24 | 14 | 0 | `insufficient_clusters` |
| False refusals (Ask, Deny or Escalate on a benign case) | 10/24 | 10/24 | 24 | 0 | 0 | `insufficient_clusters` |

- On both sides, all 48 semantic cases were attempted and inspected. No case was incomplete, error, unknown,
  unobserved or not run, and no run timed out.
- Rule CI-1 (`mcp_result_evidence_incomplete_*` counts as incomplete) applied to no case.
- The three technical cases are reported separately and are the same on both sides: `t01` was inspected (Allow), and
  `t02` and `t03` were over budget and not inspected.
- The 14 changes are all `Allow -> Deny` on attack cases. Benign verdicts did not change: 14 were Allow and 10 were
  Deny on both sides.
- The predeclared dependency-and-family grouping gives 2 resampling units, which is 1.087 effective clusters against
  the SOU-153 minimum of 10. No interval is reported, and the overall change is `not_established`. The paired
  transitions are descriptive.
- "Improved" and "regressed" are per-case transition labels on this public corpus. They are descriptive, not a
  statistical inference, and say nothing about attack prevention, task utility or readiness.
- Latency is the microseconds of one adapter call in a debug build, for inspected cases only. It is descriptive and
  no speed-up or slow-down is stated.

  | Population | Inspected and measured (each side) | Baseline median / p95 | Candidate median / p95 |
  | --- | --- | --- | --- |
  | Attack (semantic) | 24/24 | 594 / 103252 | 5237 / 91900 |
  | Benign (semantic) | 24/24 | 701.5 / 105518 | 802.5 / 86638 |
  | Technical | 1/3 | 145 / 145 | 131 / 131 |
  | All cases | 49/51 | 669 / 105518 | 1362 / 90599 |

  - The two over-budget technical cases (`t02`, `t03`) were not inspected and have no duration. They are counted
    as `incomplete` and never pooled with inspected latency.
  - No run timed out, so no case was censored.
  - A fresh recording produces different latencies.

Full outputs: [comparison.json](comparison/comparison.json), [units.csv](comparison/units.csv) and
[report.md](comparison/report.md).

## Contents

| Path | What it is |
| --- | --- |
| [predeclaration.json](predeclaration.json) | Original predeclaration, SHA-256 `01e5e069…`, committed before any build. Never edited |
| [predeclaration-amendment-001.json](predeclaration-amendment-001.json) | Additive amendment: `--jobs 2` for both revisions, SHA-256 `1ff07638…` |
| `runs/baseline/attempt-001/` | Refused before build: rustc was not installed. Not measured |
| `runs/baseline/attempt-002/` | Build failed: out of memory, cargo exit 101. Not measured. Its log is a public derivative (below) |
| `runs/baseline/attempt-003/` | **Measurement.** Build exit 0 in 143 s; adapter exit 0 in 0.70 s |
| `runs/candidate/attempt-001/` | **Measurement.** Build exit 0 in 177 s; adapter exit 0 in 0.77 s |
| `comparison/` | Retained comparison outputs |
| [controls.json](controls.json) | 15 negative controls on temporary mutated copies of these runs; all passed |
| [SHA256SUMS](SHA256SUMS) | Digests of every other file in this directory |

The measured run directories contain `run.json`, `adapter-stdout.json` (raw adapter output, unmodified),
`adapter-stderr.txt`, `build-messages.jsonl`, `build-stderr.txt` and `report.json`. The `report.json` file is the
original `sw-result-inspection-report/1`, built by the revision's own `run_corpus.build_report`.

## Timeline (UTC, from the recording machine's clock and Git)

| Time | Event |
| --- | --- |
| 12:08:58 | Predeclaration written; committed at 12:12:44 (`6a041a52`) |
| 12:13 | Baseline attempt-001: refused before build |
| 13:18–13:19 | Baseline attempt-002: build failed (os error 1455, paging file too small) |
| 13:52:53 | Amendment 001 written; committed at 13:53:02 |
| 13:53–13:55 | Baseline attempt-003: built and executed |
| 13:56–13:59 | Candidate attempt-001: built and executed |

The two recordings ran one after the other, with nothing else heavy running. The machine had been restarted to
release memory before attempt-003. The amendment was declared after a build failure and before any adapter
execution. No detector outcome was known when it was made.

Environment, as reported by the recorder:
- rustc 1.99.1 (`58cf8f9c3`) and cargo 1.99.1, host `x86_64-pc-windows-msvc`;
- dev profile, `cargo +1.99.1 build --jobs 2 --locked -p agentfw --example result_inspection_corpus`;
- a fresh `CARGO_TARGET_DIR` on D: per attempt;
- no Cargo configuration files and no refused build variables.

The operator states that the MSVC tools were Build Tools 2022 (MSVC 14.44) with Windows SDK 10.0.22621.

## Reproduction

```powershell
python scripts/benchmarks/result_inspection_compare.py `
  --predeclaration docs/benchmarks/evidence/sou191/predeclaration.json `
  --amendment docs/benchmarks/evidence/sou191/predeclaration-amendment-001.json `
  --baseline docs/benchmarks/evidence/sou191/runs/baseline `
  --candidate docs/benchmarks/evidence/sou191/runs/candidate `
  --out-dir $env:TEMP\sou191-repro --expect docs/benchmarks/evidence/sou191/comparison
python scripts/benchmarks/result_inspection_controls.py --evidence docs/benchmarks/evidence/sou191 `
  --out $env:TEMP\sou191-controls.json
```

- **What it needs:** a full clone (not shallow) that contains the accepted-main commit `7eb0c2ab` (`git fetch
  origin main`) and this branch's history. The tools read only files in the repository and Git objects. They do not
  use the operator's private copy, the build directories, or any network access.
- **Comparison:** exits 0 and prints `reproduced: retained outputs are byte-identical`. This is *retained-input
  reproduction*. It re-verifies the retained runs against Git objects, recomputes the corpus digests and rebuilds
  both original reports from the raw adapter output. It does not rebuild either revision, run the detector or
  reproduce the artifact hashes.
- **Changed retained output:** with `report.md` changed, the same command printed `NOT reproduced` and exited 2.
- **Controls:** exits 0 when every control passes. `unmutated_copy` also has to reproduce the retained
  `comparison.json`.
- **Recording again:** follow the guide. The new attempts get new numbers, and fresh latencies will differ.

## Public derivative of baseline attempt-002

- **What was found:** the recorder's sanitizer at the time missed two local paths in that attempt's build log. They
  were written with doubled backslashes inside cc-rs error text. The log also contained 42 copies of the build
  process `PATH` that cc-rs prints when a build script fails.
- **What is published:**
  - `build-stderr.txt` is not published.
  - Its sanitized derivative is `build-stderr.public.txt`.
  - [PUBLIC-DERIVATIVE.json](runs/baseline/attempt-002/PUBLIC-DERIVATIVE.json) records the original's retained
    SHA-256 (`83a962ee…`), the derivative's SHA-256 (`39f061bb…`) and the procedure.
  - The procedure is the recorder's current sanitizer, applied once. It changes those 44 lines and nothing else.
  - `run.json` and `build-messages.jsonl` in that directory are the original retained bytes. `run.json` still names
    `build-stderr.txt` and its original digest.
- **Where the original is:** the operator keeps it outside Git. The local, unpublished commit that held it was
  replaced before publication, and no published commit contains it.
- **Limit:** a public reader can check the derivative's digest, but cannot check that it was derived from the
  original. That needs the private copy.
- The recorder now covers both forms, so later attempts did not need a derivative.

## Custody limitations

- The link from source to binary is attested by the recording machine, not proven. That link covers:
  - Cargo's artifact message;
  - the fresh target directory;
  - the checks of the checkout before and after the build;
  - the artifact hash before and after execution.

  There is no signature. A malicious recording machine, a modified toolchain or a consistently fabricated run
  directory cannot be detected offline. Debug MSVC builds are not expected to be bit-reproducible, so rebuilding will
  not reproduce the artifact hashes `b8543c20…` and `1772d62a…`.
- **Recorder identity is checked, under one declared transformation.** `recorder_sha256` and `contract_sha256`
  hash the recorder and contract files as they were on disk. The comparator requires both hashes, for a measured
  attempt, to match blobs that are present together in one commit reachable from HEAD. It accepts each blob in
  exactly two forms: its raw bytes, or, for a blob with no CR, every LF written as CRLF (a Windows checkout with
  `core.autocrlf=true`). Anything else is `recorder_unidentified`, and a control tests this.
  - The result is in each attempt's `recorder_source` in `comparison.json`.
  - Both measurements resolve to commit `95072f50`. The recorder blob `b20538ed` matches in the `lf_to_crlf` form
    (`80a77778…`); the contract blob `6db93680` matches exactly.
  - Baseline attempt-001 resolves to `6a041a52` and attempt-002 to `9098c79f`, both exactly.
  - This identifies which committed source the recorded bytes correspond to. It does not prove that the recording
    machine ran those bytes; that is part of the attestation above.
- **Clock times.** Declaration and run times come from the recording machine's clock. The order "amendment before
  measurement" is enforced by the attempt sequence. The commit order is local history, not a third-party timestamp.
  `52f4e980` is a re-created copy of the sanitizer fix, made when the unpublished commit holding the original
  attempt-002 was removed. Attempt-002 was therefore committed (`e5b30c8b`) after its recording time.
- **Untranslated problem text.** Attempt-001's `problems` entry is the Windows error text in the system's
  non-English locale, kept as recorded. It shows up as unreadable text in `comparison.json`. It means that `rustc`
  was not found. The recorder now writes an English message for this case.
- **Controls harness bug.** The first run of the controls on these bundles failed 10 of its 12 controls with
  `custody_incomplete`. The harness copied only the measured attempt and dropped the failed baseline attempts, and the
  comparator correctly refused the gap. The harness now copies whole role directories, and that failure mode is
  itself a control (`failed_attempts_dropped`). The failed output was not retained.
- **Derived outputs regenerated.** `comparison/` and `controls.json` were regenerated after the final review. The
  review made latency populations explicit, added the recorder identity check and stricter record-shape checks.
  The retained runs, predeclaration and amendment did not change. The semantic counts, transitions and denominators
  are the same as in the first comparison.
- **These runs used the earlier recorder's capture.** All four attempts here were recorded before bounded capture
  was added. That recorder held each process's whole output in memory until the process exited.
  - For every retained stream here, the process exited by itself, nothing timed out or was truncated, and the
    largest stream was 193 KB against a 2 MiB limit. So each `raw_sha256` is the digest of the complete stream.
  - The comparator accepts this earlier entry format. The recorder identities above point to that earlier recorder.
  - The measurements were not regenerated for the new capture code.
- **Bounded capture from now on.** The current recorder reads each stream on its own thread, keeps at most the
  limit in memory, and hashes every byte it observes.
  - An adapter stdout or build stdout over its limit kills the process tree, and the attempt is classified
    `output_limit_exceeded`. The adapter output is then never parsed and its cases are unobserved.
  - stderr beyond its limit is drained and discarded.
  - A digest is labelled `raw_sha256` only for a complete stream: EOF reached and the process not killed. Otherwise
    `raw_sha256` is null and `observed_sha256` covers only the bytes read.
  - Cleanup uses a Windows Job Object (POSIX: a process group). Each record states how many job processes and
    reader threads were still alive afterwards.
