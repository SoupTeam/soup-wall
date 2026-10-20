# pilot_readonly_v1 (SOU-97 candidate)

This is a separately identified candidate for the read-only filesystem and Git pilot profiles.
**It is not selected by default, it is not packaged, and it has no held-out result.** The frozen,
rev2 and `git_readonly_v1` artifacts are unchanged byte for byte.

- File: `rule_baseline/pilot_readonly_v1/rule_baseline.py`, sha256 `82a41dded79cf560cefc5ab6894e9f247d31fec2992b2b7b6d0fcad02c0494f4`
  (LF on every platform via `.gitattributes`)
- `REVISION = "pilot_readonly_v1"`, `INTERFACE = "sw-classifier-core/0.4"`, `THRESHOLD = 0.5`
- Derived from `git_readonly_v1` (sha256 `8a57c58d…18474`). The only change is a 70-line addition:
  `FS_READ_SCHEMAS`, `_workspace_path`, `_text_list`, `_bounded_fs_read`, and one branch in `_classify`.
- Explicit selection, with the digest verified by the caller:
  `AGENTFW_CLASSIFIER=rule-baseline AGENTFW_RULE_BASELINE=<abs path to this file>`. Offline:
  `python3 eval/eval_runner.py <fixtures> --classifier-path rule_baseline/pilot_readonly_v1 --out-dir <out>`.
  Nothing in the runtime, drivers, CI or profiles selects it.
- Regressions: `rule_baseline/test_pilot_readonly.py`. Evidence: `eval/evidence/sou97/candidate/`.

## What changed against git_readonly_v1

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
- every array holds at most 256 strings (the profile's `MAX_ITEMS`), each at most 4096 characters
  with no control characters, and `paths` is non-empty.

The tool description and `server_id` are never consulted. When any of these checks fails, the call
goes to the unchanged `git_readonly_v1` rules and the output is byte-identical. The schema hash is
semantic evidence only. Discovery pinning, registry/argument admission, native policy and the OS
sandbox remain the authority.

### directory_tree

The baseline returns `unknown`: neither `directory` nor `tree` is a verb, and `path` and
`excludePatterns` carry no evidence. This produced Ask (`classifier_ask`) for a supported read. The
proof resolves it without adding any name vocabulary.

### The 200-value inspection bound (MAX_LEAVES) versus the profile's 256-item arrays

The generic walker stops after 200 argument values and then reports `truncated`, which caps
confidence at 0.2 (uncertainty 0.8, so native Ask). The profile admits arrays of up to 256 items.
For the three proof tools, the proof checks every item itself: at most 256 bounded strings, well
inside the 1 MiB classifier input and 262 144-byte frame limits. Because nothing is left unexamined,
it clears the walker's `truncated` flag. `MAX_LEAVES` and every other generic bound are unchanged.

Forms that still abstain, deliberately and as in the baseline:
- arrays of more than 256 items, which the profile refuses anyway;
- patterns longer than 4096 characters;
- patterns containing control characters.

**Verified limit (corrected in Increment 3A).** The pinned schemas declare no `maxLength` for
`pattern` or `excludePatterns` items. The profile's input validator therefore applies its default
string bound, `DEFAULT_STRING_BYTES = 16 * 1024` (`crates/agentfw/src/mcp/input.rs`), so it admits
each such string up to 16 384 UTF-8 bytes. The earlier statement here, "up to 65 536 characters",
was wrong: 65 536 is the cap on an explicit `maxLength`, which these schemas don't have.

A pattern of 4097 characters up to 16 384 bytes, or one containing control characters, is admitted
by the profile but abstained on by this candidate (`unknown`, so native Ask). That is a benign false
interruption in the safe direction, not an unsupported input. The frozen matrix has no such case.
`rule_baseline/test_pilot_readonly.py` (LongPatternLimit) pins this boundary and the profile
constant.

Raising the proof's per-string bound to the profile's 16 384 bytes would be a candidate change with
a new sha256. It needs owner approval and is not part of this revision.

## Unchanged known limits

- `move_file` → `read, write` without `delete` (PMF-U05).
- `git_reset` and `git_checkout` → `unknown` (PMG-U03, PMG-U04).

All three tools are refused by the selected profiles before dispatch. `write` on a ReadOnly baseline
and `unknown` both already stop native execution. They are reported as risky misses and are not
changed here.

The D06 masking of null, array or non-JSON arguments is inherited from the frozen and
`git_readonly_v1` rules (PMF-V01 to V03, PMG-V01; v0.5 E01 and E02).
