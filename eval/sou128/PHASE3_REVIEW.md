# SOU-128 Phase 3 review

Development evidence only. Every case label is `pending`: 79 in the frozen v0.3 corpus, 83 in the default v0.4 corpus (section 9.3), 89 after the D01 additions (section 11). Nothing here is label correctness, native policy, production MCP admission or original-server execution. Sections 1 to 8 describe the v0.3 corpus; section 9 describes v0.4.

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

Development evidence on the same Windows host as section 3, measured on the v0.3 corpus (79 cases, 52 relations). Section 9 gives the v0.4 results. Nothing here scores a label, observes native policy, production MCP admission or original-server execution, or selects a candidate by default.

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
  - Rebuilding the corpus re-cites only that file: relations `a82ae6a3160be842998a74241eb24bd0c218319aedf65d940780cb55b73c7918`, fixture unchanged. These are v0.3 values; section 9.6 gives the v0.4 values.
  - The in-repo candidate then passes, including its own boundary probes.
- **Candidate latency was not measured.** `--latency` timed the baselines only. *Superseded:* section 9.1 adds candidate timing.
  - Re-measured baselines on this host, p50 / p95 ms:
    - generic: direct warm 0.097 / 0.197; worker warm 0.219 / 0.404; worker start-to-ready 45.1 / 51.0.
    - git: direct warm 0.057 / 0.076; worker warm 0.258 / 0.304; worker start-to-ready 42.9 / 48.3.
  - 0 calls over the deadline. No threshold is applied.
- **Unchanged from section 7** (Git coverage is revised in section 9.3):
  - No Git cases for invalid names, mixed known/unknown, bounds, Unicode or literals (`certain_noop`, `masked_error`, `risk_loss` and `slow` have no Git effect).
  - No reviewed labels.
  - No Linux or CI run of this gate.
  - Order invariance is not shown on the production sorted-key path.

## 9. Candidate latency, label audit, corpus v0.4 and Rust gaps (2026-10-28)

Same Windows host and candidate identity as section 8 (`ea5614df`, `pilot_readonly_v1.1`, `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e`). Measured at `metamorphic_runner.py` blob `514a9fd2b863ab44b800669611aff5119bd8737d3779d1d5195afcbb629c474f` on the v0.4 corpus.

### 9.1 Candidate latency

`--latency` with `--candidate` now also times the profiles the candidate replaces.
- The method, the deadlines (REQUEST 1400 ms, START 1400 ms), batch size 1, the nearest-rank percentiles and `time.perf_counter_ns` are unchanged.
- The candidate is timed after the baselines in the same process. Its results go to `latency.json` `candidate.classifiers` and `candidate.profiles`; the baseline `profiles` block is unchanged and `classifiers` records the baseline identities.
- `report.json` is byte-identical with and without `--latency`. Tested by `test_candidate_latency_is_separate_and_leaves_the_report_unchanged`.

Command: `metamorphic_runner.py --candidate generic=PATH --candidate git=PATH --latency` (5 warm repeats, 20 cold samples). Host: Windows 11 10.0.22631, CPython 3.12.10, 8 logical CPUs. p50 / p95 ms:

| profile | measurement | n | baseline | candidate | over deadline (b / c) |
|---|---|---|---|---|---|
| generic | direct warm (in process) | 360 | 0.092 / 0.170 | 0.078 / 0.582 | – |
| generic | direct cold (process per call) | 20 | 47.0 / 66.8 | 48.9 / 51.2 | – |
| generic | worker warm round trip | 360 | 0.224 / 0.406 | 0.212 / 0.896 | 0 / 0 |
| generic | worker cold: start to ready | 20 | 43.3 / 46.5 | 44.0 / 48.2 | 0 / 0 |
| generic | worker cold: first reply | 20 | 0.750 / 0.900 | 0.782 / 0.896 | 0 / 0 |
| git | direct warm (in process) | 55 | 0.072 / 0.122 | 0.058 / 0.102 | – |
| git | direct cold (process per call) | 20 | 47.6 / 50.8 | 48.4 / 51.1 | – |
| git | worker warm round trip | 55 | 0.209 / 0.403 | 0.254 / 0.446 | 0 / 0 |
| git | worker cold: start to ready | 20 | 42.4 / 46.3 | 43.8 / 48.2 | 0 / 0 |
| git | worker cold: first reply | 20 | 0.715 / 0.818 | 0.700 / 0.816 | 0 / 0 |

There were 0 timeouts in every row. No threshold is applied, because none is approved. These are single-host development numbers, not Linux, CI or production measurements, and not a claim that one classifier is faster.

### 9.2 Label audit (83 pending labels; none promoted)

No fixture in the repository carries a reviewed label: every one is `provisional` or `pending`. The gate refuses a promoted label by design (`test_label_promotion_is_refused`), and no reviewer approval exists. **No label was changed or promoted, and no label was inferred from a classifier output.**

The sources consulted:
- the reviewed contract `contract/updated_contract2.md` (taxonomy section 2 and D01–D10);
- the pinned upstream tool lists of `profiles/mcp/{filesystem,git}-readonly-v1`;
- the read-only tool sets that native admission admits (`crates/agentfw/src/mcp/server_profile.rs` `classify_manifest`; `server_profile/git.rs`).

Upstream `annotations` (for example `readOnlyHint`) are tool metadata. Under D04 they cannot establish an action, so they are not used as a basis.

Each case was assigned by these rules, in order:
- **A — determined by one accepted rule (5).** `tool_name` is absent or not a string. D06 routes this to `classifier_invalid`. No taxonomy judgement is involved, but promotion still needs a reviewer.
  - Cases: `NAME-01`, `NAME-02`, `NAME-04`, `NAME-05`, `GIT-NAME-01`.
- **B — derivable, needs reviewer approval of one bridge (33).** The tool is in the admitted read-only set, the case carries the exact pinned upstream schema, and every argument is schema-declared. The derivation is: taxonomy section 2 `read`; D04 for an added description; taxonomy rule 3 for literal patterns; so `actions: ["read"], unknown: false`.
  - The bridge to approve: "admitted by the reviewed read-only profile, with the pinned upstream identity" becomes a classifier oracle. That links a native admission decision to a classifier label, which is a reviewer's call.
  - Cases: `ORDER-READ-A/B`, `META-READ`, `ORDER-SIZES-A/B`, `META-SIZES`, `ORDER-SEARCH-A/B`, `META-SEARCH`, `ORDER-GITLOG-A/B`, `META-GITLOG`, `DEFAULT-DTREE-*` (2), `DEFAULT-SEARCH-*` (2), `DEFAULT-SIZES-*` (2), `DEFAULT-GITDIFF-*` (2), `DEFAULT-GITLOG-*` (2), `ARRAY-199`, `ARRAY-200`, `UNICODE-*` (6), `LITERAL-RM-A/B`, `GIT-BOUND-LOG-20`.
- **B-bound — as B, plus a bound decision (3).** The contract-level label would be `read` / `unknown: false`. The bound relations, however, deliberately allow added uncertainty here, and the native profile refuses `max_count` 21. A reviewer must decide whether the oracle is the contract-level label.
  - Cases: `ARRAY-201`, `ARRAY-256`, `GIT-BOUND-LOG-21`.
- **C — needs reviewer authoring (42).** No reviewed source fixes the outcome.
  - Blank names (2): `NAME-03`, `GIT-NAME-02`. A whitespace-only string is a string; the contract does not say whether it violates the admitted schema.
  - Pinned but not admitted mutation tool (3): `DEFAULT-EDIT-*` (2), `OBSERVE-EDIT-DRYRUN-TRUE`. `edit_file` is `selected_profile_mutation_unsupported`, and whether `dryRun: true` is a proven no-op is not stated.
  - Synthetic tools without a pinned definition (37): `delete_file`, `workflow_batch`, `shell_exec` and `unknown_vendor_command` cases (`ORDER-`/`META-` DEL, MIX, SHELL, UNKNOWN; `MIXED-*` (8); `DEPTH-*` (4); `LITERAL-QUOTED-A/B`), `RENAMED-1..5` and `STRARG-01..06`. D05 bounds shell parsing, but what a synthetic `shell_exec` executes is not defined by any pinned source.

Total: 5 + 33 + 3 + 42 = 83. The rules are mechanical, so a reviewer can re-derive the assignment from the fixture, the two tool lists and the two admitted sets.

### 9.3 Corpus v0.4: bounded Git-classifier coverage

The v0.3 files are unchanged (`4d71bcd3…` fixture; `794202c4…` relations). v0.4 appends **4 pending cases and 3 relations** after every v0.3 item:
- fixture `1897deef9e4afd5b5d2088075a68db8520f9867e898c174eaa9d245663d196ee`;
- relations `a11d3896ed84e0320eda8ad85b80c7294bafabb0da96e68c666baea40d4b82a3`.

`make_sou128_corpus.py --check` requires v0.4 to keep the frozen v0.3 items as an exact prefix:
- cases are compared byte-for-byte after parsing;
- relations and probes are compared with only `sources[].sha256` removed, so a re-citation is accepted but a changed rule, basis, path, member or kind is not.

Inclusion was decided before any outcome was seen. A candidate addition needed an invariant from an accepted contract rule, a Git code path or control not already covered, and a bounded size.

| Gap | Decision | Basis |
|---|---|---|
| Argument bounds | **Added** `S128-GIT-BOUND-LOG-20/21` and relation `BOUND-GITLOG-20-21` (`no_silent_loss_past_bound`) | D01, D08. The Git classifier proves `max_count` only within 1..20 (`_bounded_git_read`, cited). `context_lines` uses the same loop, so it would be redundant. |
| Invalid names | **Added** `S128-GIT-NAME-01` (`null`) and `-02` (`"   "`), relations `GIT-NAME-01/02` (`technical_failure_channel`) | D06. These are the two disjuncts of the Git classifier's own check `not isinstance(name, str) or not name.strip()`; more types would reach the same branch. |
| Mixed known/unknown | **Not added** | An undeclared Git argument is both an "unmodeled parameter" (D01, so `unknown = true`) and "an input that violates the admitted schema" (D06, so `classifier_invalid`). Neither outcome is source-determined; a reviewer must resolve it. |
| Unicode, literals | **Not added** | They would be observation-only relations with no assertion. |

Results: all 3 new relations pass **informatively** (not vacuously) for the baseline and the candidate, in both modes.
- At `max_count` 21 the Git baseline drops `read` and sets `unknown = true`, which the relation permits. It now appears as the third known-action loss: risky lost none, uncertainty added.
- The relation review now finds `certain_noop/git` (breaks `BOUND-GITLOG-20-21`) and `masked_error/git` (breaks `GIT-NAME-01/02`) effective.
- `risk_loss/git` still has no effect: no Git case has a risky action together with an unknown component, which is the reviewer-blocked mixed case.
- `slow/git` also has no effect, by control design: `slow` delays only `search_files`.

### 9.4 Rust admission-boundary gaps

| Probe | Request-path Rust test on `main` | Status |
|---|---|---|
| Duplicate member in `arguments` | `native_mcp_rejects_ambiguous_and_unsupported_client_messages_before_execution`: a duplicate `url` must fail closed with no execution (since `7052a64b`) | covered by an existing test; not executed by this gate |
| Duplicate tool name | none | proposed below |
| `NaN` in `arguments` | none | proposed below |
| Lone surrogate in `arguments` | none | proposed below |

The narrowest regression is three raw messages added to that existing table-driven test, which already asserts fail-closed with an empty execution ledger. The fixture tools `read_document` and `delete_note` already exist there:

```rust
r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_document","name":"delete_note","arguments":{}}}"#,
r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_document","arguments":{"n":NaN}}}"#,
r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_document","arguments":{"s":"\ud800"}}}"#,
```

**Not implemented here, on purpose.**
- `crates/agentfw/tests/mcp_admission.rs` belongs to the MCP-admission owners, not SOU-128.
- It cannot be validated here: this host has no Rust toolchain, the gate cannot run Rust, and the `test` job is deferred on Draft PRs and skipped on `main` pushes.
- The expected rejections follow from source but are unexecuted:
  - duplicate name: `Strict` `visit_map`;
  - `NaN`: `serde_json` has no such token;
  - lone surrogate: `serde_json` 1.0.154 string parsing.

The four probes stay `blocked`.

### 9.5 Results (v0.4)

| Check | Result |
|---|---|
| `make_sou128_corpus.py --check` (including the frozen prefix) | OK |
| Baseline gate, direct and worker | `PASS`: 38 pass, 0 fail, 17 observed, 3 vacuous; probes 6 pass, 4 blocked |
| Candidate gate, direct and worker | `PASS`: 38 pass, 0 fail, 17 observed, 2 vacuous; candidate probes 6 pass, 4 blocked; no direct/worker divergence |
| Baseline / candidate accounting (both modes) | certain 58 / 62; partial unknown 6 / 4; abstention 10 / 8; proven no-op 2 / 2; technical failure 7 / 7 (`classifier_invalid`); classified pairs 37; known-action losses 3, none without added uncertainty; labels scored 0, pending 83 |
| Candidate comparison | 4/83 cases changed (`DEFAULT-DTREE-ABSENT/EXPLICIT`, `ARRAY-201/256`); 0 risky losses; 0 relation regressions |
| Relation review | every asserted relation broken by a targeted control; none broken only by the untargeted one; no effect: `risk_loss/git`, `slow/git` |
| Broken-candidate controls (wrapping the candidate) | all 8 detected. Exit 1: `order_sensitive`, `metadata_obedient`, `default_sensitive`, `risk_loss`, `masked_error` (also `GIT-NAME-01/02`), `certain_noop` (also `BOUND-GITLOG-20-21`). Exit 2: `fake_success`, `slow`. |
| `test_sou128_metamorphic.py` | 25 tests OK |
| `report.json` | byte-identical across runs and with or without `--latency` |

### 9.6 Remaining gaps

- No reviewed labels. Section 9.2 gives what a reviewer can approve and what must be authored.
- Git mixed known/unknown awaits a contract decision between D01 and D06 for undeclared arguments.
- Rust request-path regressions for duplicate tool name, `NaN` and lone surrogate (section 9.4).
- After #213 merges, `eval/eval_runner.py` must be re-cited. In a trial merge with `ea5614df` the rebuild produces relations `88950e88490890199293e281c66b10a0a7599f3b0898a713bf75cb04b65186dc`, the fixture stays `1897deef…`, `--check` passes with v0.3 still frozen, and the full suite passes.
- No Linux or CI run of this gate. Order invariance is not shown on the production sorted-key path.

## 10. Git boundary probes, label ownership and the D01/D06 decision request (2026-10-28)

### 10.1 Defect fixed: the Git classifier's boundaries were never probed

Section 8.5 extended the boundary probes to a candidate's *generic* classifier. The Git classifier (`rule_baseline/git_readonly_v1/rule_baseline.py`) is a separate file with its own single-shot `main()`, and it was never probed, for the baseline or for a candidate. A Git-only candidate whose `main()` answered truncated JSON with an ordinary classification therefore got `PASS` (exit 0).
- Reproduced by `test_git_candidate_boundaries_are_probed_too`.
- **Fix:** the same probes and verdict rules now also run against the Git classifier and are recorded under `boundary_probes_git` and `boundary_probes_git_classifier`, for the baseline and for a candidate. A failing probe fails the run, and the generic keys are unchanged.
- The accepted Git baseline and the SOU-97 candidate each give 6 pass and the same 4 blocked; the masking Git candidate gives 3 fail.
- `report.json` stays deterministic. The suite now has 26 tests, and all 8 broken-candidate controls are still detected.

### 10.2 Are reviewed labels required for this gate?

The contract assigns them elsewhere: "SOU-13 owns reviewed labels/splits" (`contract/updated_contract2.md`, section 1.2). Section 8 also states that "provisional developer labels do not establish a production accuracy gate".
- Every SOU-128 assertion is a relation between two observed classifier outputs. None compares an output with a label, and `labels.scored` is 0 by construction.
- Reviewed labels are therefore not an input this metamorphic gate needs. Section 9.2 lists which labels a reviewer could approve if SOU-13 or the TL wants them for later accuracy accounting.
- This reading rests on the contract and this review. It has not been checked against the current Linear task text.

### 10.3 D01 versus D06 for an undeclared argument: decision request

**Sources.**
- D01 (section 3.1): "When some actions are proven but unmodeled parameters remain, proven actions are preserved alongside `unknown: true`."
- D06 (section 3.2): `classifier_invalid` covers "an input that violates the admitted schema/profile".
- None of the pinned upstream schemas sets `additionalProperties`. Under JSON Schema an undeclared member is therefore *allowed* by the upstream schema.
- The selected read-only profiles treat a missing `additionalProperties` as closed (`crates/agentfw/src/mcp/input.rs`, `"MCP objects must explicitly be closed"`). The real-server path validates arguments and refuses (`"MCP arguments violate the selected input profile"`) before a call is queued for `admit()`, which is where classification happens.
- So under the selected profiles the classifier never sees an undeclared argument. Generic native admission (`crates/agentfw/src/mcp/admission.rs`) classifies arguments without that schema check.

**Counterexamples.** Observed outputs of the accepted baselines; the SOU-97 candidate gives the same. These are observations, not labels.

| ID | Invocation (pinned upstream schema) | Observed | Under D01 | Under D06 (closed profile) | Open upstream schema |
|---|---|---|---|---|---|
| CE-1 | `git_log {"repo_path":"/workspace","max_count":5,"author":"x"}` | `actions: [], unknown: true` | must keep `read`, `unknown: true` | `classifier_invalid` | no violation |
| CE-2 | `read_text_file {"path":"/workspace/notes.txt","mode":"raw"}` | `read`, `unknown: false` | `read`, `unknown: true` | `classifier_invalid` | no violation |
| CE-3 | `edit_file {path, edits, "backup": true}` | `write`, `unknown: false` | `write`, `unknown: true` | `classifier_invalid` | no violation |

SOU-97 already records the CE-2 shape (its PMF-A01) as a pending safety violation of the generic read rule.

**Decision requested (TL).** For classifier semantics outside the closed selected profiles, is an argument absent from the pinned tool schema:
- (a) an unmodeled parameter under D01 (keep proven actions, `unknown: true`);
- (b) a D06 `classifier_invalid` input; or
- (c) out of classifier scope, because admission must close the schema first?

What SOU-128 would do in each case:
- (a): add `preserve_risk_mark_unknown` relations for CE-1/2/3. The accepted baselines would fail them, which is a classifier-owner fix.
- (b): add `technical_failure_channel` relations. The baselines would also fail.
- (c): record the cases as observation only.

Until then nothing is added. `risk_loss/git` stays without effect because it depends on this case.

**Decided 2026-10-29 (TL review of #246): (a).** Implemented in section 11 with a new rule, `preserve_actions_mark_unknown`, because `preserve_risk_mark_unknown` needs a risky source action (section 11.1).

### 10.4 State at the end of this section

- Pushed PR head `90b18d10` with CI: 8 success (Draft fast checks, admission, CodeQL and its five analyses) and 14 skipped by the Draft policy. The Rust `test` job is among the deferred ones.
- Local commit `d52ecf84` (section 10.1) is not pushed.
- `eval/eval_runner.py` stays cited at main's `86dded74…` until #213 merges (section 9.6). Re-citing earlier would break the gate on the current base.

## 11. D01 extra-argument relations CE-1/2/3 and the SOU-97 v1.2 candidate (2026-10-30)

This section implements the TL decision in @winux125's 2026-10-29 review of #246, which answers section 10.3:
- Outside the closed selected profile, an argument the schema permits but does not declare is unmodelled semantics under D01. Established actions are preserved and `unknown` is set to `true`.
- An actual violation of an explicitly admitted or closed schema stays invalid and refused under D06.
- The selected filesystem/Git profiles still close the schema and refuse such a call before classification. That path is unchanged and not exercised here.
- The relations concern classifier semantics only. They say nothing about original-server authorization.

Same Windows host as section 3, on the v0.4 corpus.

### 11.1 Rule: `preserve_actions_mark_unknown`

Section 10.3 option (a) proposed `preserve_risk_mark_unknown`. That rule needs a *risky* source action, so CE-1 and CE-2 (source `read`) would always be "inconclusive". `eval/metamorphic_runner.py` therefore adds one rule. `preserve_risk_mark_unknown` and its controls are unchanged.

`preserve_actions_mark_unknown` passes only if all of these hold:
1. Both members classify. A technical failure fails the relation, even through an established D06 channel; it is never counted as a valid classification.
2. The source proves a nonempty set of actions with `unknown: false`. An abstaining or already-uncertain source fails as "inconclusive" instead of passing vacuously.
3. Every proven source action survives in the variant. A lost action fails, whatever its risk.
4. The variant has `unknown: true`. Suppressed uncertainty fails.

### 11.2 Cases and relations (appended to v0.4)

`eval/tools/make_sou128_corpus.py` appends 6 cases with origin `sou128_v0.4_d01_extra_argument` and 3 relations, after the existing v0.4 Git items.
- The frozen v0.3 prefix is unchanged, as are the 83 earlier v0.4 cases and the 55 earlier relations (citations included).
- The probes are unchanged.
- `--check` now also requires the added origins to appear in order: Git coverage first, then D01.
- All 89 labels stay `pending` with null expectations. None is promoted.

| Relation | Source case (schema-declared arguments only) | Variant adds | Pinned schema |
|---|---|---|---|
| `EXTRA-ARG-CE1` | `git_log {"repo_path":"/workspace","max_count":5}` (Git classifier) | `"author":"x"` | `git-readonly-v1/upstream-tools-list.json` |
| `EXTRA-ARG-CE2` | `read_text_file {"path":"/workspace/notes.txt"}` | `"mode":"raw"` | `filesystem-readonly-v1/upstream-tools-list.json` |
| `EXTRA-ARG-CE3` | `edit_file {"path":"/workspace/notes.txt","edits":[{"oldText":"a","newText":"b"}]}` | `"backup":true` | same |

Each relation cites:
- `contract/updated_contract2.md` D01 (section 3.1, the "unmodeled parameters" sentence) and D06 (section 3.2, `classifier_invalid` scope);
- the pinned tool list, for the fact that the key is undeclared and `additionalProperties` is unset;
- the PR #246 TL review, cited by name only (no file hash).

The builder asserts both schema facts. It refuses to build if the schema declared the key or closed itself; `D01ExtraArgument.test_a_closed_schema_is_not_built_as_a_d01_case` covers this. `edit_file` appears only in the upstream tool list. Nothing here treats it as admitted by the read-only profile.

**Source hashes:** none changed. The new citations reuse the hashes already cited: contract `a3c85a29…`, filesystem tools `d9df6889…`, Git tools `8819c85d…`. Integrated main does not touch any cited source (11.6).

New files: fixture `fc5c920b4103db4792c8aa0a4b06c6ac793392118bd51baded03ed2bed3875f1`, relations `a810b3ecb83b89118f4ed426b34ee455c9548026066104685eaff70e7836fe1c`.

### 11.3 Baseline failures (reproduced before the assertions existed; kept as failures)

The accepted baselines were run on the CE inputs before any relation was written. The gate then reproduces the same outputs in both modes:

| Relation | Source → variant (direct = worker) | Verdict |
|---|---|---|
| `EXTRA-ARG-CE1` (Git baseline) | `ok [read] false` → `unknown [] true` | **fail**: proven actions lost: `['read']` |
| `EXTRA-ARG-CE2` (generic baseline) | `ok [read] false` → `ok [read] false` | **fail**: unknown not set |
| `EXTRA-ARG-CE3` (generic baseline) | `ok [write] false` → `ok [write] false` | **fail**: unknown not set |

These are classifier-owner defects. No oracle, label or relation kind was changed to hide them. The baseline gate therefore reports `FAIL` (exit 1): 38 pass, 3 fail, 17 observed, 3 vacuous, in both modes, with no direct/worker divergence and probes 6 pass / 4 blocked for each classifier.

`report.json` now records `verdict_by_side` (`baseline`, `candidate`). The overall `verdict` is still the worse side. `summary.md` lists each side's failures and the relations a candidate fixes.

### 11.4 SOU-97 candidate `pilot_readonly_v1.2`

- Source: `rule_baseline/pilot_readonly_v1/rule_baseline.py` at #213 head `7d7f974776c1312ce425f98734281891815b6943` (`refs/pull/213/head`, checked 2026-10-30).
- sha256: `ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30`.
- #213 is still an unmerged Draft. The candidate is not imported or merged into this branch, and it is never selected by default (`CANDIDATE_BLOCKER` names v1.2).
- It was extracted from the commit object and selected with `--candidate generic=PATH --candidate git=PATH`.

| | baseline (direct = worker) | candidate (direct = worker) |
|---|---|---|
| relations pass / fail / observed | 38 / 3 / 17 | 41 / 0 / 17 |
| vacuous passes | 3 | 2 (`META-UNKNOWN`, `ORDER-UNKNOWN`) |
| certain / partial unknown / abstention / proven no-op / technical (`classifier_invalid`) | 63 / 6 / 11 / 2 / 7 | 65 / 7 / 8 / 2 / 7 |
| labels scored / pending | 0 / 89 | 0 / 89 |
| boundary probes (generic, Git) | 6 pass, 4 blocked each | 6 pass, 4 blocked each |
| side verdict | `FAIL` | `PASS` |

Candidate CE outcomes, in both modes:
- CE-1: `[read] false` → `[read] true`.
- CE-2: `[read] false` → `[read] true`.
- CE-3: `[write] false` → `[write] true`.

The candidate gives reason code `unmodelled_argument` for each.

Comparison, in both modes:
- 7/89 cases changed: the 4 from section 9.5 plus the three CE variants.
- 0 risky losses and 0 relation regressions.
- Relation fixes are exactly `EXTRA-ARG-CE1/2/3`.

The overall run is `FAIL` (exit 1) because the baseline side fails.

### 11.5 Negative controls

`eval/sou128_controls.py` adds `D01_CONTROLS`. They wrap any classifier via `write_control(..., base=PATH)`. They are kept out of `CONTROLS`, so the baseline relation review keeps its control set. Each was wrapped around the v1.2 candidate (generic and Git) and run in both modes:

| control | exit / candidate side | CE-1/2/3 verdict (direct = worker) | other failures |
|---|---|---|---|
| `extra_arg_action_loss` | 1 / `FAIL` | fail: proven actions lost | none |
| `extra_arg_unknown_suppressed` | 1 / `FAIL` | fail: unknown not set | none |
| `extra_arg_technical_failure` (`classifier_invalid`) | 2 / `TECHNICAL_ERROR` | fail: technical failure on a case that must classify | none |
| `vacuous_source` (abstains wherever certain) | 1 / `FAIL` | fail: inconclusive, source proves no action | `MIXED-*` (4), also correctly inconclusive |

The judge-level tests also cover the following without the candidate:
- action loss, with and without uncertainty;
- suppressed `unknown`;
- a technical failure on either member;
- abstaining, certain-empty and uncertain sources;
- the unchanged `preserve_risk_mark_unknown` rule for a read source.

The relation review now handles the baseline's own failures:
- It lists them under `failing_on_baseline` (`EXTRA-ARG-CE1/2/3`) and credits them to no control.
- A control's broken relations are those that pass on the baseline.
- "No effect" means nothing breaks beyond the baseline's own failures.
- The review exits 1 while baseline failures remain.

Result: every other asserted relation is broken by a targeted control, and none only by `fake_success`. Vacuous relations are `DEFAULT-DTREE`, `META-UNKNOWN` and `ORDER-UNKNOWN`. No effect: `risk_loss/git` (CE-1's lost action is `read`, which is not risky) and `slow/git`.

### 11.6 Integration and checks

- Fetched accepted `main` `49e89b6b` (#296). Its 67 changed files include nothing under `eval/`, `contract/`, `rule_baseline/` or `profiles/`, and no cited source or worker/admission input. Merged into this branch as `886617f6` (non-fast-forward, conflict-free, no rebase); every cited hash is unchanged after the merge.
- `make_sou128_corpus.py --check`: OK (89 cases, 58 relations, 8 + 2 probes).
- `test_sou128_metamorphic.py`: 34 tests. `test_eval_runner.py`, `test_eval_scores.py` and `test_eval_failure_channel.py` are OK. After the merge, the baseline + candidate gate `report.json` is byte-identical across two runs.
- **Candidate reproducibility.** The two `SOU97CandidateD01` tests read the classifier blob from commit `7d7f9747` and refuse any other SHA-256. The tests never use the network.
  - Where the object is absent, which is any clone that has not fetched it, the class is **skipped** with `CANDIDATE NOT AVAILABLE, NOT TESTED`. That is not a pass.
  - With `SOU128_REQUIRE_SOU97_CANDIDATE=1` the absence is an error instead.
  - `test_candidate_pin_matches_the_runner` always runs offline. It checks that this pin equals the one `CANDIDATE_BLOCKER` publishes.
  - The README section "SOU-97 candidate" gives the reviewer procedure.
- **Clean-checkout trial (2026-10-30).** A standalone `--single-branch` clone (no shared object store, no `7d7f9747`) plus this diff gave:

  | Mode | Result |
  |---|---|
  | Default | 32 run, OK; `SOU97CandidateD01` skipped (2 tests, explicit reason) |
  | Strict, before fetch | `FAILED (errors=1)`, a setUpClass error. Under `-k SOU97` the exit is 5 (Python 3.12: no test ran) |
  | After the documented fetch | see below |

  The documented fetch was `git fetch origin 7d7f9747…` from `github.com/SoupTeam/soup-wall`; `refs/pull/213/head` also resolved to `7d7f9747`. The fetched blob's sha256 was `ffeb367f…ada30`. After it, strict mode gave 34 run, OK, 0 skipped.
- **Local shared repository.** The object is present here, so 34 run, OK, 0 skipped.
- Not rerun: the eight earlier broken-candidate controls (section 9.5) and latency. Neither the controls nor the classifier timing path changed, so only the D01 controls were run against v1.2. The section 9.1 candidate latency was measured on v1.1.

### 11.7 Remaining

- **Baseline failures:** `EXTRA-ARG-CE1` (Git baseline: action loss) and `EXTRA-ARG-CE2/3` (generic baseline: suppressed `unknown`). They remain until a classifier owner fixes the baselines or a reviewed candidate replaces them.
- **Candidate failures:** none.
- **Native probes:** still `blocked`: duplicate argument, duplicate tool name, `NaN`, lone surrogate. They have not been independently verified, and no Rust/native result is claimed.
- **Labels:** all 89 `pending`. None is promoted, including the 6 new ones.
- **Unchanged contract gap:** CE-3 is a classifier-only statement about `edit_file`. Whether any profile admits it is out of scope.
- **Re-cite after #213 merges:** `eval/eval_runner.py` still needs re-citing then (section 9.6).
