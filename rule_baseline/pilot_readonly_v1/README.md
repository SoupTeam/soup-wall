# pilot_readonly_v1.1 (SOU-97 candidate)

This is a separately identified candidate for the read-only filesystem and Git pilot profiles.
**It is not selected by default, it is not packaged, and it has no held-out result.** The frozen,
rev2 and `git_readonly_v1` artifacts are unchanged byte for byte.

- File: `rule_baseline/pilot_readonly_v1/rule_baseline.py`, sha256 `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e`
  (LF on every platform via `.gitattributes`)
- `REVISION = "pilot_readonly_v1.1"`, `INTERFACE = "sw-classifier-core/0.4"`, `THRESHOLD = 0.5`
- Derived from `git_readonly_v1` (sha256 `8a57c58d…18474`). The only additions are
  `FS_READ_SCHEMAS`, `FS_ARGS`, the `FS_MAX_*` bounds, `_utf8_len`, `_workspace_path`, `_glob_list`,
  `_path_list`, `_bounded_fs_read`, and one branch in `_classify`.
- Explicit selection, with the digest verified by the caller:
  `AGENTFW_CLASSIFIER=rule-baseline AGENTFW_RULE_BASELINE=<abs path to this file>`. Offline:
  `python3 eval/eval_runner.py <fixtures> --classifier-path rule_baseline/pilot_readonly_v1 --out-dir <out>`.
  Nothing in the runtime, drivers, CI or profiles selects it.
- Regressions: `rule_baseline/test_pilot_readonly.py`. Current evidence: `eval/evidence/sou97/v1.1/`.

## Revision history

| Revision | sha256 | Commit | Status |
|---|---|---|---|
| `pilot_readonly_v1` | `82a41dded79cf560cefc5ab6894e9f247d31fec2992b2b7b6d0fcad02c0494f4` | `ef0d17b` | Superseded. Its results in `eval/evidence/sou97/candidate/` and `eval/evidence/sou97/pilot_report/` are historical development results and are **not** evidence for v1.1. |
| `pilot_readonly_v1.1` | `9f4a532b5d1b1f6d375eba1e9a2ffca1164bfab038bdc6fa3532cbd9584eef1e` | this revision | Current candidate. |

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
goes to the unchanged `git_readonly_v1` rules and the output is byte-identical. The schema hash is
semantic evidence only. Discovery pinning, registry/argument admission, native policy and the OS
sandbox remain the authority. Because the proof inspects every value itself, it clears the generic
walker's `truncated` flag. `MAX_LEAVES` (200 values) and `MAX_LEAF_CHARS` (4096 characters) are
unchanged for every other call.

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
