# SOU-128 Phase 3 review

Development evidence only. All 79 case labels are `pending`; nothing here is label correctness, native policy, production MCP admission or original-server execution.

## 1. Relation review (52 relations: 35 asserted, 17 observation only)

Observation-only relations are never scored; they are listed under `observe` and counted as `observed`. `eval/tools/sou128_relation_review.py` runs the gate once per broken classifier in `eval/sou128_controls.py`, wrapping both the generic and the Git baseline, and records which asserted relations each control breaks.

| Finding | Evidence | Action |
|---|---|---|
| Every asserted relation is broken by at least one **targeted** control | Relation review: `unbroken_asserted` = none; `broken_only_by_untargeted` = none | Enforced by `RelationReview.test_every_asserted_relation_is_sensitive` |
| The first review found 6 relations no control could break | The Git relations had no Git-wrapped controls; the order control collapsed to an abstention, which cannot change a relation whose answer is already an abstention | Git-wrapped controls added; the order control now adds an action |
| `DEFAULT-EDIT` was broken only by `fake_success` | `edit_file` is already a `write`, so a control that adds `write` changed nothing | `default_sensitive` adds `send_data` instead; the review now fails on untargeted-only breaks |
| 3 relations pass vacuously (equal abstentions) | `ORDER-UNKNOWN`, `META-UNKNOWN`, `DEFAULT-DTREE` (the generic baseline abstains on `directory_tree`) | Reported as `pass_vacuous`. They are still broken by targeted controls; their passes show nothing about classification quality |
| 4 control/profile pairs have no effect | `certain_noop`, `masked_error`, `risk_loss`, `slow` on Git: no Git case covers invalid names, mixed known/unknown, bounds or slow tools | Reported as a coverage gap, not hidden |
| `no_silent_loss_past_bound` permits certainty when actions are kept | A complete proof beyond the generic leaf bound can be valid. For example, the unmerged SOU-97 candidate proves `read_multiple_files` reads beyond 200 items | Deliberately not tightened to "`unknown` must be true past a bound"; that stricter rule is not source-backed |
| Order relations do not describe the production worker path | The daemon re-serializes with sorted keys (audit §4.1) | Stated in the README and audit; order invariance is shown for direct and Python boundaries only |
| Default relations rest on JSON Schema `default` annotations | The upstream implementations are not vendored | `review_status` records this on each relation |

## 2. Accounting

Each mode reports exact denominators: certain actions, proven no-op, partial unknown, abstention, technical failure by channel (expected and unexpected), protocol errors and timeouts.

Losses are computed between the two members of a relation. They are **relative to the observed source case**, never to a label. On the accepted baselines, both modes show 36 classified pairs, and the only known-action losses are `BOUND-DEPTH-4-5` and `BOUND-DEPTH-4-20` (`delete` → abstention). Both come with added uncertainty, so there are 0 losses without uncertainty. The labels section always reports `scored: 0, pending: 79`.

## 3. Latency

Batch size 1, sequential, nearest-rank percentiles, `time.perf_counter_ns`. The accepted deadlines (REQUEST 1400 ms, START 1400 ms) are read from `worker.rs` and enforced unchanged. Results go to `latency.json`, outside the deterministic `report.json`. No threshold is applied, because none has been approved.

Host: Windows 11 (10.0.22631), CPython 3.12.10, AMD64, 8 logical CPUs. Command: `python3 eval/metamorphic_runner.py --latency` (5 warm repeats, 20 cold samples).

| profile | measurement | n | p50 ms | p95 ms | over deadline |
|---|---|---|---|---|---|
| generic | direct warm (in process) | 360 | 0.107 | 0.208 | – |
| generic | direct cold (process per call) | 20 | 58.6 | 72.9 | – |
| generic | worker warm round trip | 360 | 0.318 | 0.598 | 0 |
| generic | worker cold: start to ready | 20 | 52.0 | 62.3 | 0 |
| generic | worker cold: first reply | 20 | 0.924 | 1.221 | 0 |
| git | direct warm (in process) | 35 | 0.068 | 0.081 | – |
| git | direct cold (process per call) | 20 | 52.6 | 60.0 | – |
| git | worker warm round trip | 35 | 0.407 | 0.614 | 0 |
| git | worker cold: start to ready | 20 | 47.3 | 56.0 | 0 |
| git | worker cold: first reply | 20 | 0.858 | 1.088 | 0 |

These numbers describe this host only. They are not a Linux, CI or production measurement.

## 4. Candidate comparison

The only relevant candidate is SOU-97 `pilot_readonly_v1.1`, and it exists only in unmerged Draft PR #213. It is not imported, and no other classifier is substituted. `rule_baseline/rev2` on `main` is a different classifier, not this candidate.

`--candidate NAME=PATH` runs an explicitly selected file through the same assertions in each mode. It reports per-case changes (lost, gained and risky-lost actions; `unknown` changes) and per-relation verdict changes. The mechanism is tested with a broken control as the candidate. The report records `candidate.status = not_run` with the blocker.

## 5. The four blocked parsing-boundary cases

| Probe | Python boundaries (single-shot and worker `input_json`) | Production enforcement | Existing Rust test on `main` | Validated here without Rust? |
|---|---|---|---|---|
| Duplicate member in `raw_arguments` | accepted (last wins) | recursive strict visitor, `crates/agentfw/src/mcp/admission.rs` | `tests/mcp_admission.rs` (~1690): duplicate member in `params._meta` is closed with no execution. Not in `arguments`. | **No** |
| Duplicate `tool_name` | accepted; a read becomes `delete` | same visitor | none specific | **No** |
| `NaN` | accepted | `serde_json` has no `NaN` token; the visitor also rejects non-finite numbers | none on the request path | **No** |
| Lone surrogate `\ud800` | accepted | `serde_json` rejects unpaired surrogates | `real_server/frames.rs` (~695): **response** frames only | **No** |

What Python can and does validate:
- The worker **frame** rejects a duplicate member and a wrong input hash (exit 3, no reply).
- All four inputs are accepted by both Python boundaries, so the gap is visible in every report.

What follows from source but is not tested:
- On the daemon path the worker input is produced by `serde_json::to_string` of a `serde_json::Value`, which cannot carry a duplicate key, a non-finite number or a lone surrogate. These four inputs therefore cannot reach the worker through the daemon.

Production admission behaviour still needs Rust execution: the existing `test` job on a Ready PR, or new request-path tests for `arguments`-level duplicates, `NaN` and lone surrogates. Those tests would be a separate, Rust-owned change.

## 6. Coverage gaps (unchanged by this phase)

- No Git cases for invalid names, mixed known/unknown, bounds, Unicode or literals.
- No reviewed labels.
- No Linux or CI run of the gate yet.
- Order invariance is not shown on the production (sorted-key) path.
