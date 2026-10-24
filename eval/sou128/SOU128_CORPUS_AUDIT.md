# SOU-128 independent corpus audit (Phase 0)

Status: **audit only**. No case label has been promoted, nothing has been scored and no
implementation exists yet. The v0.2 preparation files are untrusted development material.

## 1. Scope and sources

| Item | Identity |
|---|---|
| Accepted `main` | `a2fb3bf6ed95f126a6522ad569f34240fc0f226a` (Merge PR #233), branch `feat/sou128-metamorphic-contract-gate` |
| `sou128_public_development_v0.2.json` | sha256 `1d97974dab154d70041d7e26f1ba5f9b45ecae4d491f05f8c36ee0fb60b35995` (79 896 bytes, LF) |
| `sou128_relations_v0.2.json` | sha256 `55b68633f39ea6b1c1aae8a5dea420e604ae35b414af22fd25ae4acbbbfe3e82` (9 595 bytes, LF) |
| Filesystem baseline `rule_baseline/rule_baseline.py` | sha256 `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| Git baseline `rule_baseline/git_readonly_v1/rule_baseline.py` | sha256 `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474` |
| Worker framing `rule_baseline/runtime/worker.py` | sha256 `ecd1d972a034f05676d44d4bf9ce7f74f15ced4605a70d18721db63f118ca38c` |
| Original filesystem tools `profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json` | sha256 `d9df6889798a48dee9ad78b557dfd638eb618ec580adbd75923af0f64e48f954` |
| Original Git tools `profiles/mcp/git-readonly-v1/upstream-tools-list.json` | sha256 `8819c85d38867065dd429515e612f25300811a304e8f9235a46bed943e02ff9b` |
| Classifier contract `contract/updated_contract2.md` (SOU-10 v0.4) | committed blob sha256 `a3c85a29c85cf8eb2cbb30155e4dd0d696970d99206541c8aa1c6fca0100dcf0` |

All identities are sha256 of the committed blob, the bytes a Linux checkout holds. An earlier draft of this table recorded the contract's Windows `core.autocrlf` working-copy hash (`7ebf6924…`); that is not a portable identity. The other files above are stored with `eol=lf` or `-text`, so their working-copy and blob hashes are equal.

No SOU-13/SOU-35 sealed or private material and no SOU-97 (#213) or SOU-109 (#215) unmerged
file was read or used. Observations below were made with the accepted baselines only.

Method: my own scripts parsed both files with a duplicate-key-rejecting loader. They checked
every relation against `main` sources and ran the accepted filesystem baseline in three modes:
- **direct**, in-process `classify()` as `eval/eval_runner.py` calls it;
- **single-shot**, the `rule_baseline.py` stdin process;
- **worker**, the daemon's exact `WORKER_BOOTSTRAP` text (`crates/agentfw/src/classifier_runtime/worker.rs:48-65`)
  with `worker.py`, driven by a local harness, not by the Rust daemon.

All observations are unscored.

## 2. Counts (structural, not coverage)

| Measure | Value |
|---|---|
| Records | 69 (69 unique ids) |
| Distinct semantic inputs (canonical JSON) | 61 |
| Byte-distinct serialized inputs (insertion order kept) | 69 |
| Canonical duplicates | exactly the 8 `ORDER-*-A/B` pairs |
| Relations | 28: 8 `semantic_equal`, 8 `no_authority_escalation`, 4 `semantic_equal_if_profile_default_confirmed`, 4 `observe_literal_context`, 4 `preserve_known_risky_actions` |
| Relations the v0.2 checker can score | 12 (8 order + 4 mixed); the other 16 are recorded but never evaluated |
| Dangling references | 0 |
| Shared seeds | 8 seeds (`ORDER-*-A`) serve as the source of 2–3 relations each; 11 relations point at a case of another group |
| Cases in no relation | 24 (renamed 5, serialized 6, invalid name 5, depth 4, size 4) |
| Expectation status | 69/69 `pending`; all `expected` fields null |

**Distinct contract assertions are far fewer than the counts suggest.** The 8 order relations make one assertion (key order is irrelevant) over 8 seeds. The 8 metadata relations make one assertion with **one identical description string**. Most remaining families reuse the same 8 seeds.

`validate_fixture()` from `main`'s `eval/eval_runner.py` accepts the v0.2 fixture (0 errors), so the case shape fits the accepted evaluator.

`build.py` is deterministic: the content matches byte-for-byte once CRLF is normalized. On Windows, however, `Path.write_text` writes CRLF, so the file it writes differs from the hash it prints. In-repo fixtures already get `eol=lf` from `.gitattributes` (`eval/fixtures/*.json`).

## 3. Seeds against the pinned original schemas

The pinned schemas declare no `additionalProperties`. The selected read-only profiles use a closed argument validator, so undeclared fields are refused before classification (see SOU-110 `docs/operations/LITERAL_MCP_ARGUMENTS.md`).

| Seed tool | In a pinned profile? | v0.2 arguments vs pinned schema |
|---|---|---|
| `read_file` | yes (filesystem) | `encoding` undeclared (schema: `path`, `head`, `tail`) |
| `list_directory` | yes (filesystem) | `recursive` undeclared (schema: `path` only) |
| `search_files` | yes (filesystem) | `case_sensitive` undeclared (schema: `path`, `pattern`, `excludePatterns` default `[]`) |
| `read_multiple_files` | yes (filesystem) | valid shape |
| `git_status` | yes (Git) | uses `repository` and `short`; schema requires only `repo_path` |
| `delete_file`, `shell_exec`, `workflow_batch`, `unknown_vendor_command` | **no** | synthetic classifier inputs, not tools of any pinned server |

The Git baseline proves a read only when four conditions hold (`git_readonly_v1/rule_baseline.py:617-652`):
- `tool_schema` matches the pinned schema hash;
- the arguments are a subset of the allowed set;
- `repo_path` is exactly `/workspace`;
- `max_count` and `context_lines` are within their bounds.

Every v0.2 Git case is `unknown` under both baselines, including a corrected `{"repo_path": "/workspace/repo"}` that lacks `tool_schema`. The corpus has no case that can prove a Git read.

## 4. Relation findings

### 4.1 Object order: retain, but the boundary assumption is wrong for the daemon
- **Grounding:** JSON objects are unordered (RFC 8259 §4). The accepted filesystem classifier is order-sensitive in principle: shell evidence joins argument leaves in walk order (`rule_baseline.py:643`). So this is a real invariant to test.
- **Observed:** 8/8 equal under direct, single-shot and worker modes.
- **Correction:** on the production path the daemon re-serializes the semantic input with `serde_json::to_string` (`classifier_runtime/worker.rs:538`). serde_json is built without `preserve_order` (no `indexmap` dependency in `Cargo.lock`), so keys are **sorted** before the worker sees them. The order pairs are therefore byte-identical on the daemon → worker path. They test the direct, single-shot and other Python boundaries, not the production wire.

### 4.2 Misleading metadata: wrong relation; a supported replacement exists
- **Problem with v0.2:** `no_authority_escalation` is a policy/authority property. Classifier output carries no authority, so the relation cannot be decided from classifier results, and v0.2 never scores it.
- **Supported replacement:** contract D04 (§4.1, registry row D04) says description metadata does not dictate actions. That makes "actions and `unknown` unchanged by an added `tool_description`" a source-backed classifier relation.
- **Observed:** 8/8 unchanged.
- **Still pending:** the authority (no permission grant) control needs native policy evidence and remains separate.
- **Gap:** one fixed description only. Add a description claiming destructive effects on a read tool, and one claiming read-only on a delete tool.

### 4.3 Optional defaults: **all 4 relations invalid; remove**
Every variant adds an argument the pinned schema does not declare (`recursive`, `short`, `case_sensitive`, `encoding`). The Git seed also uses a non-schema argument name. These are not default equivalences; under the profiles they are refusals.

Source-declared defaults that could replace them:
- `search_files.excludePatterns=[]`
- `directory_tree.excludePatterns=[]`
- `list_directory_with_sizes.sortBy="name"`
- `git_diff`/`git_diff_staged`/`git_diff_unstaged.context_lines=3`
- `git_log.max_count=10`

The Git replacements need the exact pinned `tool_schema` in the input. JSON Schema `default` is an annotation, and the upstream server code is not vendored. Any replacement therefore stays `pending` until the default semantics are reviewed, with the schema path cited.

### 4.4 Unicode and literal data: observational; one case misgrouped
- `UNICODE-NFC` and `UNICODE-CYR` are canonically equivalent (NFC-equal) but byte-distinct. Linux path and search semantics are byte-based, so treating them as "observe, never assert equal" is correct.
- `LITERAL-RM` is not a Unicode case: it appends `; sudo` to a search pattern.
- `LITERAL-QUOTED` classifies as `[]`, `unknown: false`. That is consistent with the D07 no-op and D05 literal handling, but it's still unscored.
- Unicode appears only in `pattern`. There are no Unicode paths and no NFC/NFD in paths.

### 4.5 Mixed known and unknown: supported
- **Grounding:** D01 ("partially known actions are preserved with `unknown = true`") and D09.
- **Observed:** 4/4 keep the risky action and change `unknown` from false to true.
- **Checker gap:** the v0.2 checker verifies only that risky actions are a subset. It doesn't require `unknown == true` on the variant that added an unknown component.
- **Still unestablished:** each source's risky label is itself a pending case expectation.

### 4.6 Unpaired families
- **Renamed (5):** observational only.
  - `RENAMED-1` is `read_file`, a real tool name, not an unknown one.
  - Names drive classification: `totally_safe_read` gives `read` with `unknown: false`, and `vendor_delete_now` gives `delete`.
  - The classifier treats names as evidence, never as authority. Authority comes only from the installed registry.
- **Serialized boundary (6):** these are malformed JSON *strings inside valid JSON*. The classifier runs `json.loads` on string `raw_arguments` and keeps a raw leaf on failure (`rule_baseline.py:620-624`). All 6 classify as `read` from the tool name. They exercise that lenient path; **they prove nothing about parser rejection**.
- **Invalid names (5):** all return `status: error` with `failure.code: classifier_invalid`, an established D06 channel (`eval/eval_runner.py` `FAILURE_CODES`). They are candidates for `expected.technical_failure: classifier_invalid` after review.
- **Depth (4):** the boundary is wrong.
  - The accepted classifier gives `delete` at v0.2 depth parameter 4 and `unknown` with no actions from parameter 5 onward.
  - All v0.2 depth cases (6, 7, 9, 20) are past the boundary; none tests it.
  - Past the bound, the known `delete` becomes `unknown: true`, which D08 gates as Ask. It is not a silent allow.
- **Size (4):** 199 and 200 give `read`, `unknown: false`; 201 and 256 give `read`, `unknown: true` (leaf bound `MAX_LEAVES=200`). This straddles the classifier bound correctly. The profile limit (`MAX_ITEMS=256`, `crates/agentfw/src/mcp/input.rs`) is a different bound.

## 5. Parsing boundaries (real raw-byte probes)

| Boundary | Duplicate key | Duplicate `tool_name` | NaN | Lone surrogate `\ud800` | Trailing comma or truncated | Invalid UTF-8 | > 1 MiB |
|---|---|---|---|---|---|---|---|
| Single-shot stdin (`rule_baseline.py:758`) | accepted, last wins | accepted; **`read_text_file`→`delete_file` gives `delete`** | accepted | accepted | `classifier_invalid` | `classifier_invalid` | `classifier_invalid` (size) |
| Worker `input_json` (`worker.py:69`) | accepted | accepted (same flip) | accepted | accepted | `classifier_invalid` | not frameable | `classifier_invalid` (size) |
| Worker frame (`worker.py:49`) | **rejected**: exit 3, no reply | – | – | – | – | – | – |
| MCP admission (`crates/agentfw/src/mcp/admission.rs:774-807`) | **rejected** recursively ("duplicate JSON member"); non-finite rejected | – | – | – | – | – | – |

**Conclusions:**
- The enforcing boundary is the Rust MCP admission parser, which can't be run here (no Rust toolchain).
- The Python semantic-input boundaries are lenient. On the daemon path that is mitigated by re-serialization (§4.1), but any direct caller can create an ambiguous parse.
- A SOU-128 boundary test must send raw bytes to the real boundary. It must not change worker process management, deadlines or security policy.

## 6. Coverage gaps (handoff item 5)

Missing from the corpus:
- valid optional `default`/absent/`false`/`true` variants;
- Git cases with the pinned `tool_schema`;
- Unicode in paths;
- a depth boundary that actually straddles the bound;
- the byte limit (1 MiB) as a case;
- duplicate or malformed JSON at a real boundary;
- metadata variants beyond one string;
- a known-risk case that becomes unknown past a bound;
- worker error and **timeout** behaviour (`classifier_timeout` can't be observed in-process; `eval_runner.py:171`).

Direct and worker modes both exist and agreed on all 69 cases for the filesystem baseline.

## 7. Corpus corrections

Every row below is applied in v0.3 by `eval/tools/make_sou128_corpus.py`, with two notes:
- the checker change lives in `eval/metamorphic_runner.py` (`preserve_risk_mark_unknown`);
- the new Unicode-path cases are observations only, never asserted equal.

| Action | Cases |
|---|---|
| Retain the relation; reword the boundary claim | `ORDER-*` (8) |
| Replace the relation with D04 actions/`unknown` invariance; keep the authority control separate and pending | `META-*` (8) |
| **Remove**; replace with schema-declared defaults, kept pending | `OPTION-*` (4 relations, 5 records) |
| Regroup as a literal-data case | `LITERAL-RM` |
| Relabel as "classifier string-argument parsing"; add real raw-byte boundary tests | `RAW-01…06` |
| Candidate `expected.technical_failure: classifier_invalid` | `NAME-01…05` |
| Add threshold cases at parameter 4 and 5 | `DEPTH-*` |
| Add Git cases with the pinned `tool_schema`; add Unicode-path cases | new |
| Add a check that `unknown` becomes `true` | `preserve_known_risky_actions` checker |

**Promotions from pending: none.** Each candidate above has a source, but needs review before any label is scored.

## 8. Blockers

- The SOU-97 candidate (`pilot_readonly_v1.1`, #213) is not merged. Candidate-versus-baseline comparison is blocked, and nothing from #213 is borrowed.
- The metadata → permission control needs native policy evidence (Rust); there's no Rust toolchain on this machine.
- The `classifier_timeout` channel needs a worker-level timeout harness that doesn't change the accepted deadlines.
- The production parsing boundary can only be exercised through Rust tests or a real daemon run.
