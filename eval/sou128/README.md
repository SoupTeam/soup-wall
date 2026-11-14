# SOU-128 metamorphic classifier contract gate (development)

A bounded gate that checks **relations between classifier outputs**: an original case against each transformed case. It runs in-process (`direct`) and through the existing classifier worker framing (`worker`).

It is a development gate. All 89 case labels are `pending`. The gate refuses a promoted label (exit 3), and [PHASE3_REVIEW.md](PHASE3_REVIEW.md) section 9.2 records which labels could be justified for review.

It does **not** observe native policy, authority decisions, production MCP admission (Rust) or original-server execution. It never selects the SOU-97 candidate by default, because #213 is not merged. The candidate's comparison by explicit identity is recorded in [PHASE3_REVIEW.md](PHASE3_REVIEW.md) sections 8, 9 and 11.

**Current verdict on the accepted baselines: `FAIL` (exit 1).** They genuinely fail the three D01 extra-argument relations `EXTRA-ARG-CE1/2/3` (section 11) in both modes; every other asserted relation passes. The SOU-97 `pilot_readonly_v1.2` candidate, selected explicitly, passes all of them. `report.json` records each side under `verdict_by_side`; the overall `verdict` stays the worse side.

## Reproduce

```sh
python3 eval/tools/make_sou128_corpus.py --check    # corpus = deterministic build from pinned sources
python3 eval/metamorphic_runner.py --out-dir target/sou128             # report.json + summary.md
python3 eval/metamorphic_runner.py --latency --out-dir target/sou128   # also latency.json (this host only)
python3 eval/tools/sou128_relation_review.py --out-dir target/sou128-review
python3 -m unittest discover -s eval -p 'test_sou128_metamorphic.py' -v
```

Options:
- `--classifier generic=PATH` or `--classifier git=PATH` replaces a classifier for the whole run. The default is the accepted baselines `rule_baseline/rule_baseline.py` and `rule_baseline/git_readonly_v1/rule_baseline.py`.
- `--candidate NAME=PATH` keeps the baselines and also runs an explicitly selected candidate. The report then includes per-case and per-relation comparisons. The boundary probes also run against the candidate's generic and Git classifiers (`candidate.boundary_probes`, `candidate.boundary_probes_git`), and a failing candidate probe fails the run. No candidate is selected by default, and the SOU-97 candidate is not in this branch while #213 is unmerged.
- `--modes direct` skips the worker.
- `--latency` (with `--latency-repeats N`, `--latency-cold N`) measures batch-1 latency of the baselines and, with `--candidate`, separately of the profiles the candidate replaces (`latency.json` `candidate.classifiers` and `candidate.profiles`). `report.json` stays byte-identical with or without it; timings go to `latency.json` only.

### SOU-97 candidate (opt-in, not vendored)

The SOU-97 `pilot_readonly_v1.2` classifier exists only in unmerged Draft PR #213. This branch neither contains nor imports it, and the default classifiers stay the accepted baselines. A fresh clone of this branch does not have its commit object, so the two `SOU97CandidateD01` tests then **skip** with `CANDIDATE NOT AVAILABLE, NOT TESTED`. That means the candidate was not tested; it is not a pass. To qualify the candidate independently:

```sh
git fetch origin 7d7f974776c1312ce425f98734281891815b6943          # exact #213 head, by full SHA (read-only)
# fallback if fetching by SHA is refused: git fetch origin refs/pull/213/head && git rev-parse FETCH_HEAD   # must print 7d7f9747...
git cat-file blob 7d7f974776c1312ce425f98734281891815b6943:rule_baseline/pilot_readonly_v1/rule_baseline.py > /tmp/sou97_v1_2.py
sha256sum /tmp/sou97_v1_2.py      # must be ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30
python3 eval/metamorphic_runner.py --candidate generic=/tmp/sou97_v1_2.py --candidate git=/tmp/sou97_v1_2.py --out-dir target/sou128-sou97
SOU128_REQUIRE_SOU97_CANDIDATE=1 python3 -m unittest discover -s eval -p 'test_sou128_metamorphic.py' -v   # absence is an error, not a skip
```

The tests themselves read the blob from that exact commit and refuse any other SHA-256. They never use the network. Expected with the candidate: `verdict_by_side` = baseline `FAIL` (CE-1/2/3), candidate `PASS` (41/41 asserted relations in both modes); overall exit 1.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Every executed assertion passed |
| 1 | An assertion, boundary probe or mode-parity check failed |
| 2 | An unexpected technical error |
| 3 | Invalid input, cited-source drift, or a promoted label |

## Files

| File | Role |
|---|---|
| `eval/tools/make_sou128_corpus.py` | Builds the corpus from the pinned tool schemas; every relation cites `path`, `rule` and `sha256`. `--check` also requires v0.4 to keep the frozen v0.3 items as an exact prefix |
| `eval/fixtures/sou128_metamorphic_dev_v0.4.json` | Default corpus: 89 cases (the 79 frozen v0.3 cases, 4 Git cases, then 6 D01 extra-argument cases) in the accepted `eval_runner` fixture format |
| `eval/fixtures/sou128_relations_v0.4.json` | Default relations: 58 (52 frozen, 3 Git, then 3 D01 extra-argument), 8 raw-byte boundary probes, 2 worker frame probes |
| `eval/fixtures/sou128_*_v0.3.json` | Frozen v0.3 corpus (79 cases, 52 relations); never rewritten |
| `eval/metamorphic_runner.py` | The gate. Each case is scored by `eval_runner.evaluate_case`; this module adds relations, worker mode, probes and provenance |
| `eval/sou128_controls.py` | Negative controls: the unchanged generic or Git baseline plus one defect each (test input only) |
| `eval/tools/sou128_relation_review.py` | Runs every control and reports which asserted relations each breaks, vacuous passes and coverage gaps |
| `eval/test_sou128_metamorphic.py` | Positive control, negative controls, relation sensitivity, accounting, candidate path, reproducibility, input integrity |
| `eval/sou128/SOU128_CORPUS_AUDIT.md` | The independent audit of the v0.2 preparation that v0.3 corrects |
| `eval/sou128/PHASE3_REVIEW.md` | Relation review, accounting, latency, blocked boundary cases; section 8 covers the integration with main and the SOU-97 candidate comparison; section 9 covers candidate latency, the label audit, v0.4 and the Rust gaps; section 10 covers Git boundary probes, label ownership and the D01/D06 decision request; section 11 implements the TL's D01 decision (CE-1/2/3) |

## Assertions

| Kind | Rule | Source |
|---|---|---|
| `equal_outcome` | Same status, actions, `unknown` and failure channel | RFC 8259 §4 (member order); pinned schema `default` (absent vs explicit default) |
| `metadata_invariant` | An added description changes neither actions nor `unknown` | contract D04 |
| `preserve_risk_mark_unknown` | Adding an unknown component keeps every risky action and sets `unknown = true` | contract D01 |
| `preserve_actions_mark_unknown` | Adding a schema-permitted argument the pinned schema does not declare keeps every action the source proves (certain, nonempty, any risk) and sets `unknown = true`; a technical failure or a source that proves nothing fails | D01 / §3.1, D06 / §3.2, pinned upstream schema, PR #246 TL review |
| `no_silent_loss_past_bound` | Past an inspection bound: more uncertainty or an established technical failure, never certainty with fewer actions | D01, D08 |
| `technical_failure_channel` | An unusable tool name fails through an established D06 channel | D06, `eval_runner.FAILURE_CODES` |
| `observe` | Recorded, never scored: Unicode, literals, renamed tools, string arguments | — |

An equality between two abstentions (`unknown` with no actions) is reported as `pass_vacuous`, not hidden in the pass count.

## Modes and boundaries

- **`worker`** runs the daemon's own `WORKER_BOOTSTRAP` and `REQUEST_DEADLINE`/`START_DEADLINE`, read from `crates/agentfw/src/classifier_runtime/worker.rs`. A missed deadline becomes an explicit `classifier_timeout`, never a classification. The harness sends members in their written order; the real daemon re-serializes with sorted keys (see the audit).
- **Raw-byte probes** go to the single-shot stdin process and to the worker's `input_json` of each classifier (generic and Git, which has its own main()), for the baseline and for a selected candidate (`boundary_probes`, `boundary_probes_git`). Truncated or invalid JSON, invalid UTF-8 and inputs over 1 MiB must fail through `classifier_invalid`.
- **Duplicate members, `NaN` and lone surrogates** are accepted by both Python boundaries. Only the Rust MCP admission parser (`crates/agentfw/src/mcp/admission.rs`) rejects them, and this gate cannot run it. They are reported as `blocked`, with the Python behaviour shown as a `known_gap`.
