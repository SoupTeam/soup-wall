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

The only relevant candidate is SOU-97 `pilot_readonly_v1.1`. It is still only in unmerged Draft PR #213, so it is not imported into this branch, and no other classifier is substituted. `rule_baseline/rev2` on `main` is a different classifier, not this candidate.

`--candidate NAME=PATH` runs an explicitly selected file through the same assertions in each mode. It reports per-case changes (lost, gained and risky-lost actions; `unknown` changes) and per-relation verdict changes, and (since section 8) probes the candidate's own parsing boundaries. The mechanism is tested with broken controls as the candidate. Without `--candidate`, the report still records `candidate.status = not_run` with the blocker.

The candidate was run by explicit identity against this branch on 2026-10-28; see section 8.

## 5. The four blocked parsing-boundary cases

| Probe | Python boundaries (single-shot and worker `input_json`) | Production enforcement | Existing Rust test on `main` | Validated here without Rust? |
|---|---|---|---|---|
| Duplicate member in `raw_arguments` | accepted (last wins) | recursive strict visitor, `crates/agentfw/src/mcp/admission.rs` | `tests/mcp_admission.rs` (~1690): duplicate member in `params._meta` is closed with no execution. *Corrected 2026-10-28:* `native_mcp_rejects_ambiguous_and_unsupported_client_messages_before_execution` (~1989, present since `7052a64b`) also sends a duplicate `url` inside `arguments` and requires fail-closed with no execution. | **No** (Rust test exists; not executed by this gate) |
| Duplicate `tool_name` | accepted; a read becomes `delete` | same visitor | none specific | **No** |
| `NaN` | accepted | `serde_json` has no `NaN` token; the visitor also rejects non-finite numbers | none on the request path | **No** |
| Lone surrogate `\ud800` | accepted | `serde_json` rejects unpaired surrogates | `real_server/frames.rs` (~695): **response** frames only | **No** |

What Python can and does validate:
- The worker **frame** rejects a duplicate member and a wrong input hash (exit 3, no reply).
- All four inputs are accepted by both Python boundaries, so the gap is visible in every report.

What follows from source but is not tested:
- On the daemon path the worker input is produced by `serde_json::to_string` of a `serde_json::Value`, which cannot carry a duplicate key, a non-finite number or a lone surrogate. These four inputs therefore cannot reach the worker through the daemon.

Production admission behaviour still needs Rust execution: the existing `test` job on a Ready PR, or new request-path tests for `arguments`-level duplicates, `NaN` and lone surrogates. Those tests would be a separate, Rust-owned change.

## 6. Portability defect found and fixed

**Defect.** The corpus builder recorded, and the gate verified, sha256 of the bytes on disk. On a Windows `core.autocrlf` checkout, LF-stored sources have CRLF working copies. The contract, `eval/eval_runner.py` and `admission.rs` were therefore cited by hashes that a Linux checkout cannot reproduce.

**Reproduced.** In a fresh clone with `core.autocrlf=false` (the bytes a Linux checkout holds), the pre-fix commit `285a244` is refused with exit 3: source drift on exactly those three files.

**Fix.** A cited source is identified by its committed blob when the working copy has no content change (`git diff` accounts for line-ending conversion), and by its disk bytes otherwise.

**Verified.** After the fix, the corpus check, the gate (PASS) and all SOU-128 tests pass in that LF clone. The `report.json` produced on Windows and on the LF clone is byte-identical.

## 7. Coverage gaps (unchanged by this phase; see section 8.6 for the current list)

- No Git cases for invalid names, mixed known/unknown, bounds, Unicode or literals.
- No reviewed labels.
- No Linux or CI run of the gate yet.
- Order invariance is not shown on the production (sorted-key) path.

## 8. Integration with main `db4f006d` and the SOU-97 candidate (2026-10-28)

Development evidence on the same Windows host as section 3. Nothing here scores a label, observes native policy, production MCP admission or original-server execution, or selects a candidate by default.

### 8.1 Integration

- Merged accepted `main` `db4f006d` (#281) into this branch. The merge was clean and changed no SOU-128 file.
- SOU-97 (#213, pushed at `ea5614df`) is **not** merged into this branch, so #246 keeps its own scope. Its candidate was used only by explicit identity (8.3).

### 8.2 Source citations

Every cited source was compared with its committed blob. One was stale:

| Cited source | Cited before | Now | Change |
|---|---|---|---|
| `crates/agentfw/src/mcp/admission.rs` (4 boundary probes) | `633b8ad3e78d491d4a5607ba488b2bb944b9bb8032cccc89a36857283f1e1d4d` | `9f0d24ef56f03ed100bd3fb6c589d9dd22ab172be133ceda66687ad6d4b56357` | re-cited |
| `contract/updated_contract2.md` | `a3c85a29…dcf0` | same | none |
| `eval/eval_runner.py` | `86dded74…0662` | same | none |
| `profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json` | `d9df6889…f954` | same | none |
| `profiles/mcp/git-readonly-v1/upstream-tools-list.json` | `8819c85d…ff9b` | same | none |
| `rule_baseline/rule_baseline.py` | `d2d43d6f…aebd` | same | none |
| `rule_baseline/runtime/worker.py` | `ecd1d972…a38c` | same | none |

The cited rule ("Strict visitor: duplicate JSON member and non-finite numbers rejected") is unchanged:
- The `Strict` deserializer and `parse()` are byte-identical in both blobs.
- `serde_json` is `1.0.154` in `Cargo.lock` before and after.
- Main added one `parse(&raw)?` call site (an internal adapter loop), which also uses `Strict`.
- Main's three new plain `serde_json::from_slice` calls are in a test and in the daemon's own HTTP refusal body. None parses host MCP requests.

The corpus was rebuilt with `eval/tools/make_sou128_corpus.py`. Only the four `admission.rs` hashes changed.
- `sou128_metamorphic_dev_v0.3.json` is byte-identical: `4d71bcd33b38db213600b95b179506177bd1d61c1e728010c64c153497f31cd7`. All 79 labels stay `pending`.
- `sou128_relations_v0.3.json` went from `a4e5f249beb29e3b003e9322360ca860bf4bbeeffd19faaec9ae4deb88711971` to `794202c41e84f0bb933ae9f0527809234210f1abf57d149dd3dac6e55d045a94`.

### 8.3 Candidate comparison

Candidate: `rule_baseline/pilot_readonly_v1/rule_baseline.py` at SOU-97 commit `ea5614dfb061e7e5c9ef197546b251b4caef9297`, revision `pilot_readonly_v1.1`, sha256 `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e`. This equals the SOU-97 gate manifest pin. It imports only the standard library, so it was extracted from the committed blob and run as `--candidate generic=PATH --candidate git=PATH`.

| | baseline (direct = worker) | candidate (direct = worker) |
|---|---|---|
| relations pass / fail / observed | 35 / 0 / 17 | 35 / 0 / 17 |
| vacuous passes | 3 (`DEFAULT-DTREE`, `META-UNKNOWN`, `ORDER-UNKNOWN`) | 2 (`META-UNKNOWN`, `ORDER-UNKNOWN`) |
| certain actions / partial unknown / abstention | 57 / 6 / 9 | 61 / 4 / 7 |
| proven no-op / technical failure (`classifier_invalid`) | 2 / 5 | 2 / 5 |
| classified pairs / known-action losses / without uncertainty | 36 / 2 / 0 | 36 / 2 / 0 |
| labels scored / pending | 0 / 79 | 0 / 79 |
| boundary probes pass / fail / blocked | 6 / 0 / 4 | 6 / 0 / 4 |
| direct/worker divergent cases | none | none |

Cases changed, in both modes:
- `S128-DEFAULT-DTREE-ABSENT` and `-EXPLICIT` go from abstention to `read`.
- `S128-ARRAY-201` and `S128-ARRAY-256` stay `read`, with `unknown` going from true to false. This is the case section 1 anticipated for `no_silent_loss_past_bound`.
- There are 0 lost or risky-lost actions and 0 relation changes or regressions.
- These are relative to the observed baseline outputs, not to labels.

`report.json` is byte-identical across repeated runs. The verdict is `PASS` (exit 0).

### 8.4 Broken-candidate controls

Each `eval/sou128_controls.py` defect was also wrapped around the SOU-97 candidate (instead of the baseline) and selected as the candidate. Every one is detected in both modes:

| control | exit | failed relations (direct / worker) | risky losses |
|---|---|---|---|
| `order_sensitive` | 1 | 8 / 8 | 0 |
| `metadata_obedient` | 1 | 8 / 8 | 3 |
| `default_sensitive` | 1 | 6 / 6 | 0 |
| `risk_loss` | 1 | 4 / 4 | 4 |
| `masked_error` | 1 | 5 / 5 | 0 |
| `certain_noop` | 1 | 6 / 6 | 4 |
| `fake_success` | 2 | 28 / 28 (`invalid_output`) | 0 |
| `slow` | 2 | 0 / 3 (11 `classifier_timeout`) | 0 |

`slow` behaves the same wrapped around the baseline: 11 worker timeouts and no direct-mode effect, because only the worker has a deadline.

### 8.5 Defect found and fixed: the candidate's boundaries were never probed

**Defect.** The raw-byte and worker-frame probes ran only against the baseline generic classifier. A selected candidate whose single-shot `main()` answered truncated or invalid JSON with an ordinary classification still got `PASS`, because in-process relations cannot observe `main()`.

**Reproduced.** The new test `test_candidate_boundaries_are_probed_and_a_masked_parse_failure_fails` builds such a candidate: the unchanged baseline `classify()` plus a masking `main()`. It exited 0 before the fix.

**Fix.** With `--candidate`, `eval/metamorphic_runner.py` now runs the same probes and verdict rules against the candidate's generic classifier and records them under `candidate.boundary_probes` and `candidate.boundary_probes_classifier`. A failing probe fails the run.
- The baseline section, the no-candidate report, the classifiers and the probe expectations are unchanged.
- The SOU-97 candidate's probes match the baseline's exactly: 6 pass and the same 4 blocked, each accepted by both Python boundaries.

### 8.6 Remaining blockers and gaps

- **The four parsing-boundary probes stay `blocked`; they need Rust to verify.**
  - Duplicate `arguments` member: an existing request-path Rust test covers it (section 5, corrected).
  - Duplicate `tool_name`, `NaN` and lone surrogate: no request-path Rust test on `main`.
  - This gate cannot run Rust, and this host has no Rust toolchain. The `test` job is skipped on `main` pushes and deferred on Draft PRs, so this review cites no execution result.
  - Production Python boundaries (`rule_baseline.py`, `runtime/worker.py`, the candidate) were not changed. On the daemon path the worker input is `serde_json::to_string(&invocation.semantic_input())` of a `serde_json::Value` (`classifier_runtime/worker.rs`, blob `f010a323…da5f`; `admission.rs` `semantic_input`), so these inputs cannot reach the worker through the daemon.
- **After #213 merges**, `eval/eval_runner.py` becomes `760085c0faf23a8409e52d6fd5ebc97bedf64fd67c0547f1d6fb33bbc5bebe6e` (purely additive) and the gate will refuse the stale citation.
  - A trial merge of this branch with `ea5614df` has no conflicts.
  - Rebuilding the corpus re-cites only that file: relations `a82ae6a3160be842998a74241eb24bd0c218319aedf65d940780cb55b73c7918`, fixture unchanged.
  - The in-repo candidate then passes, including its own boundary probes.
- **Candidate latency was not measured.** `--latency` times the baselines only.
  - Re-measured baselines on this host, p50 / p95 ms:
    - generic: direct warm 0.097 / 0.197; worker warm 0.219 / 0.404; worker start-to-ready 45.1 / 51.0.
    - git: direct warm 0.057 / 0.076; worker warm 0.258 / 0.304; worker start-to-ready 42.9 / 48.3.
  - 0 calls over the deadline. No threshold is applied.
- **Unchanged from section 7:**
  - No Git cases for invalid names, mixed known/unknown, bounds, Unicode or literals (`certain_noop`, `masked_error`, `risk_loss` and `slow` have no Git effect).
  - No reviewed labels.
  - No Linux or CI run of this gate.
  - Order invariance is not shown on the production sorted-key path.
