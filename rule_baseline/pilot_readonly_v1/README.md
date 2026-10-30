# pilot_readonly_v1.2 (SOU-97 candidate)

This is a separately identified candidate for the read-only filesystem and Git pilot profiles.
**It is not selected by default, it is not packaged, and it has no held-out result.** The frozen,
rev2 and `git_readonly_v1` artifacts are unchanged byte for byte.

- File: `rule_baseline/pilot_readonly_v1/rule_baseline.py`, sha256 `ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30`
  (LF on every platform via `.gitattributes`)
- `REVISION = "pilot_readonly_v1.2"`, `INTERFACE = "sw-classifier-core/0.4"`, `THRESHOLD = 0.5`
- Derived from `git_readonly_v1` (sha256 `8a57c58d…18474`). The only additions are
  `FS_READ_SCHEMAS`, `FS_ARGS`, the `FS_MAX_*` bounds, `_utf8_len`, `_workspace_path`, `_glob_list`,
  `_path_list`, `_bounded_fs_read`, `ORIGINAL_SCHEMAS`, `_unmodelled_keys`, and their branches in
  `_classify`.
- Explicit selection, with the digest verified by the caller:
  `AGENTFW_CLASSIFIER=rule-baseline AGENTFW_RULE_BASELINE=<abs path to this file>`. Offline:
  `python3 eval/eval_runner.py <fixtures> --classifier-path rule_baseline/pilot_readonly_v1 --out-dir <out>`.
  No default, profile, package or required CI step selects it. Only an explicit operator
  environment (below), the drivers' opt-in `--classifier-script`/`--classifier-sha256` flags, or the
  `sou97_candidate` workflow dispatch input does.
- Regressions: `rule_baseline/test_pilot_readonly.py`. Evidence for v1.2 has not been regenerated yet;
  `eval/evidence/sou97/v1.1/` and the gate manifest still describe v1.1 (see the revision history).

## Selection and rollback

The collector reads `AGENTFW_CLASSIFIER`, `AGENTFW_RULE_BASELINE` and the script's bytes once, when it
starts. Changes therefore apply to newly started collector processes, not to running ones.

**Select** (operator, explicit):

1. Verify the bytes: `sha256sum rule_baseline/pilot_readonly_v1/rule_baseline.py` must print
   `ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30`. Do not select it otherwise.
2. Start the collector with `AGENTFW_CLASSIFIER=rule-baseline` and
   `AGENTFW_RULE_BASELINE=<absolute path to that file>`.
3. Acceptance runs use the same check: `--classifier-script <path> --classifier-sha256 <sha256>`
   (both or neither), and the drivers refuse to start on a mismatch.

**Roll back** to the profile's previously selected classifier:

1. Point `AGENTFW_RULE_BASELINE` back at it, after the same digest check:
   - filesystem: `rule_baseline/rule_baseline.py`, sha256
     `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`;
   - Git: `rule_baseline/git_readonly_v1/rule_baseline.py`, sha256
     `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474`.
2. Restart the collector processes that had the candidate selected.
3. For acceptance runs, omit both flags (or leave `sou97_candidate` unset); default mode is unchanged.

Rollback changes no policy, registry, profile or stored state, because the candidate never owns any.
It cannot undo calls the candidate already admitted.

## Revision history

| Revision | sha256 | Commit | Status |
|---|---|---|---|
| `pilot_readonly_v1` | `82a41dded79cf560cefc5ab6894e9f247d31fec2992b2b7b6d0fcad02c0494f4` | `ef0d17b` | Superseded. Its results in `eval/evidence/sou97/candidate/` and `eval/evidence/sou97/pilot_report/` are historical development results and are **not** evidence for v1.1. |
| `pilot_readonly_v1.1` | `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e` | `ca13021` | Superseded by v1.2 (D01). Its evidence in `eval/evidence/sou97/v1.1/` is not evidence for v1.2. |
| `pilot_readonly_v1.2` | `ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30` | this revision | Current candidate. Offline evidence and the gate manifest are not yet regenerated for it. |

v1.2 changes one semantic rule, after the TL's D01/D06 decision on the SOU-128 review (section 10.3,
2026-10-29):

- An argument that the verified pinned original schema of the tool does not declare is an
  **unmodelled parameter** (D01): proven actions are kept and `unknown` is `true`, with reason code
  `unmodelled_argument`. See "Unmodelled arguments" below.

v1.1 changes only the bounds of the existing proof:

1. Glob patterns (`pattern`, `excludePatterns` items) are now bounded by the profile's 16 384 UTF-8
   bytes, instead of 4096 characters with control characters refused. Every admitted pattern is
   proven read-only matching data (see below).
2. Path length is measured in UTF-8 bytes, without raising an exception on text the native profile
   cannot carry. v1 raised `UnicodeEncodeError` on a lone surrogate, which turned into
   `classifier_internal_error`; v1.1 refuses the proof and keeps the `git_readonly_v1` result.
   Paths keep the profile's 4096-byte, no-control-character workspace rule.

## The proof

`_bounded_fs_read` proves `read` (weight 0.95, `unknown=false`) only for an exact original form of
`directory_tree`, `read_multiple_files` or `search_files`. Every one of these must hold:

- the tool name is exact;
- `sha256(_canon(tool_schema))` equals the pinned original input schema of
  `@modelcontextprotocol/server-filesystem` 2026.8.31;
- if a `pinned_schema` is given, it is identical;
- the argument keys are exactly the required keys plus the allowed optional ones;
- every path passes a mirror of the profile's `validate_workspace_path`: non-empty, at most 4096
  UTF-8 bytes, no control characters, no `\`, `:` or leading `~`, no empty, `.` or `..` segments,
  and absolute paths only at or under `/workspace`;
- `paths` holds 1 to 256 such paths (the profile's `MAX_ITEMS`);
- `excludePatterns` holds 0 to 256 strings, and `pattern` is one string, each at most 16 384 bytes
  of valid UTF-8 (the empty string is allowed).

The tool description and `server_id` are never consulted. When any of these checks fails, the call
goes to the unchanged `git_readonly_v1` rules and the output is byte-identical, except that an
unmodelled argument (below) also sets `unknown=true`. The schema hash is
semantic evidence only. Discovery pinning, registry/argument admission, native policy and the OS
sandbox remain the authority. Because the proof inspects every value itself, it clears the generic
walker's `truncated` flag. `MAX_LEAVES` (200 values) and `MAX_LEAF_CHARS` (4096 characters) are
unchanged for every other call.

## Unmodelled arguments (D01, v1.2)

`_unmodelled_keys` returns the top-level argument keys that are not in `properties` of the tool's
pinned original schema. It returns nothing unless all of these hold:

- the tool name is one of the 26 original tools of the two pinned servers (`ORIGINAL_SCHEMAS`);
- `sha256(_canon(tool_schema))` equals that tool's pinned original input schema (from
  `profiles/mcp/{filesystem,git}-readonly-v1/upstream-tools-list.json`);
- if a `pinned_schema` is given, it is identical.

None of those schemas sets `additionalProperties`, so an undeclared member does not violate the
upstream schema. Both original servers ignore it, verified from the pinned packages:

- `@modelcontextprotocol/server-filesystem` 2026.8.31 (integrity matches the lockfile, entrypoint
  `729dc851…9935`) registers raw zod shapes. SDK 1.32.1 `objectFromShape` wraps them in a non-strict
  `z4mini.object`, which drops unknown keys before the handler runs. `read_text_file` reads only
  `path`, `head` and `tail`; `edit_file` reads only `path`, `edits` and `dryRun`.
- `mcp-server-git` 2026.10.10 (wheel sha256 `5bd3dc57…d335`, as in `requirements.lock`): the
  `git_log` handler reads only `max_count`, `start_timestamp` and `end_timestamp` from the arguments.

When there are unmodelled keys:

1. The exact Git and filesystem proofs are applied to the declared arguments only. An undeclared key
   never extends or repairs a proof: every declared value must still pass it.
2. The generic `git_readonly_v1` argument rules still run over **all** arguments, including the
   undeclared ones, so any risky evidence they carry (a command, a recipient and body, a mode, a
   delete flag) is kept. The proof's clearing of `truncated` does not apply.
3. The result is partial: `unknown=true`, confidence at most 0.5.

An unpinned, drifted, spoofed or closed (`additionalProperties: false`) schema never takes this path,
and its output is unchanged. A violation of a closed or declared schema stays an
`args_schema_violation` with `unknown=true`. The selected profiles still close every schema and refuse
an undeclared argument before admission (`crates/agentfw/src/mcp/input.rs`, D06). This rule changes
the classifier label only: it admits nothing, and `edit_file` stays
`selected_profile_mutation_unsupported`.

Examples (v1.1 and both selected baselines gave the first value):

| Case | Call | v1.1 | v1.2 |
|---|---|---|---|
| CE-1 | `git_log {"repo_path":"/workspace","max_count":5,"author":"x"}` | `[]`, unknown | `read`, unknown |
| CE-2 | `read_text_file {"path":"/workspace/notes.txt","mode":"raw"}` | `read`, unknown=false | `read`, unknown |
| CE-3 | `edit_file {path, edits, "backup":true}` | `write`, unknown=false | `write`, unknown |

On the frozen matrix only PMF-A01 (`read_file` with `unreviewed`) and PMG-A01 (`git_status` with a
`command`) carry an unmodelled argument. PMF-A01 becomes `read`, `unknown=true`, which resolves its
pending safety observation. PMG-A01 keeps `delete` and `unknown=true` and adds the proven `read`. On the
supplement only PSF-P01 changes, in the same way (it keeps `delete`). No public fixture case changes.

## Why every admitted glob pattern is read-only (verified in 3B)

- **The profile.** The pinned schemas declare no `maxLength` for `pattern` or `excludePatterns`
  items. `crates/agentfw/src/mcp/input.rs` therefore applies `DEFAULT_STRING_BYTES = 16 * 1024` and
  admits any string up to 16 384 UTF-8 bytes, including control characters. Only paths are further
  restricted, by `validate_workspace_path`.
- **The original server.** I read `@modelcontextprotocol/server-filesystem` 2026.8.31 from the npm
  tarball. Its archive sha256 `a239da27…1b1a` and entrypoint sha256 `729dc851…9935` both equal the
  values in `profiles/mcp/filesystem-readonly-v1/upstream-identity.json`.
  - `directory_tree` (`dist/index.js`) passes each exclude pattern only to
    `minimatch(relativePath, pattern | "**/"+pattern | "**/"+pattern+"/**", {dot: true})`.
  - `search_files` (`dist/lib.js` `searchFilesWithValidation`) passes `pattern` and exclude patterns
    only to `minimatch(relativePath, …, {dot: true})`.
  - The only filesystem operations are `validatePath` and `fs.readdir` on the validated `path`. A
    pattern never names a file, a command or content.
- **minimatch 10.2.6.** Its sha512 integrity matches the lockfile. Its only input rejection is a
  pattern longer than 65 536 UTF-16 code units. A 16 384-byte UTF-8 string has at most 16 384 code
  units (16 390 with the `**/…/**` wrapping), so admitted patterns are never rejected. Even a
  rejection would be an error result, not an effect.

Glob semantics (wildcards, braces, negation, `..` inside a pattern) only select which listed
entries are returned. They cannot reach outside the validated directory walk.

## Remaining limits (unchanged, reported as they are)

- Arrays of more than 256 items, patterns over 16 384 UTF-8 bytes, and paths over 4096 bytes or with
  control characters are all refused by the profile. The candidate keeps the baseline result for
  them (an abstention).
- `read_file` and `read_text_file` with oversized values are refused by the profile as well.
- Known risky misses: `move_file` → `read, write` without `delete` (PMF-U05); `git_reset` and
  `git_checkout` → `unknown` (PMG-U03, PMG-U04). The selected profiles refuse all three tools before
  dispatch.
- D06 masking of null, array or non-JSON arguments is inherited from the frozen and
  `git_readonly_v1` rules (PMF-V01 to V03, PMG-V01; v0.5 E01 and E02).
