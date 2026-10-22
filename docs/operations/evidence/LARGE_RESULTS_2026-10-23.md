# Large original-server results: Linux evidence (2026-10-23)

Limits, behaviour and recovery are in [LARGE_MCP_RESULTS.md](../LARGE_MCP_RESULTS.md).

## Environment

| Item | Value |
| --- | --- |
| Platform | hosted Linux x86-64 container, kernel `6.18.44-fc-v140`; `platform.kind` = `linux` (not WSL2) |
| User | non-root `tester` |
| Source | implementation commit of this change, tree `0d3eacc7d6eb7cc4ea23e7174ed47ad25f33cc63` (local commit `f699f0e` before transfer), clean before and after |
| agentfw (debug) | `19c118ef717cc3e6524e6032358dd2174d1ad56ccdf5c00625d75d3c5fb49425` |
| Node 22.22.0 (official) | `1bec56ef7cfa9a76f3e0b7c0a87f220eb73f23102b9c0b4c7529a3f7c3ce7c31` |
| bubblewrap 0.13.1 | `f56b4f9760efd35d6a5884735aba5c2f578a3473d721d5a0ef710089c356cc62` |
| Claude Code 2.1.251 | `fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7` |
| Installed profile / registry / policy | `dfe4acfa...`, `63d12de1...`, `55b0f70c...` (accepted installer, unchanged) |

No paid provider, live model, private data or publication was used. The
provider is the existing owned scripted Messages stand-in.

## Reproduction on main `4828cf3`

Same files, same server, previous build:

| Read | Result on main | Session |
| --- | --- | --- |
| 16,383 / 16,384 bytes | released exactly | alive |
| 16,385 bytes, 20 / 60 / 120 KiB | `-32603` "Unsupported MCP result withheld by the selected output profile" | alive |
| 128 KiB, 129 KiB, 2 MiB, 20 x 20 KiB, 3 x 120 KiB multi-read | no reply; collector "MCP frame exceeds admission limit" | ended |

## Result on the implementation tree

`scripts/verify-large-results.py`: **passed, 21 cases, 0 skipped**. Every case
has an independent `openat` witness of the original server reading the target
file, exactly one native call admission and one native result receipt.

| Case | Text bytes | Frame bytes | Outcome |
| --- | --- | --- | --- |
| 16,383 / 16,384 / 16,385 | same | 33,242 / 33,244 / 33,246 | exact on both channels |
| 20 / 60 / 120 KiB | 20,480 / 61,440 / 122,880 | 41,526 / 124,356 / 248,602 | exact |
| text budget - 1 / at (ASCII) | 262,143 / 262,144 | 530,222 / 530,224 | exact |
| text budget at (4-byte UTF-8) | 262,144 | 524,400 | exact |
| escaped text (quotes, backslash, tab, CR, U+0001, U+001F, Cyrillic, CJK, emoji) | 122,880 | 282,740 | exact |
| envelope - 1 / at | 262,116 | 1,048,575 / 1,048,576 | exact |
| 3 x 20 KiB multi-read | 61,525 | 124,544 | exact, every file present |
| text budget + 1 (ASCII, UTF-8) | | 530,226 / 524,402 | text-budget refusal, then useful read |
| 20 x 20 KiB multi-read | | 829,738 | text-budget refusal, then useful read |
| envelope + 1 | | 1,048,577 (observed by the collector) | envelope refusal, then useful read |
| 2 MiB file | | 4,241,018 drained, never buffered | envelope refusal, then useful read |
| injection at the end of a 200 KiB file | | | withheld (`injection` high, `filesystem-profile-refuse-result-injection`), then useful read |
| `max_record_bytes: 65536`: 60 KiB / 120 KiB | 61,440 / | | exact / `native_record_over_cap` receipt, then useful read |

Host bytes equal the daemon's inspected `content_sha256` for every released
result and every correlated refusal. No refusal contains the payload marker.

Other controls:

- Secret (`AKIA...`) in a small and in a 200 KiB file: the same verdict
  (released, provenance recorded). Size does not change classification.
- Cancellation of a 2 MiB read: one correlated `-32800` reply, no second reply,
  useful read after it. The server did not open the file for the cancelled
  call (witness 1 before, 1 after, from the earlier case).
- 8 concurrent 120 KiB reads plus one 2 MiB read: 9 correlated replies, 8 exact,
  the 2 MiB one refused, useful read after it.
- Collector memory: 32,508 KiB after initialization, peak 39,044 KiB over the
  whole session (growth 6,536 KiB; the driver fails above 96 MiB).
- Workspace metadata and content unchanged; client, original server descendants
  and daemon reaped; collector `cleanup_verified` in both sessions.

Genuine Claude Code 2.1.251 (`--strict-mcp-config`, owned scripted provider,
5 provider requests): read of the 60 KiB file (the host stored the whole result,
62,136 bytes, and its `content` equals the file exactly), the 2 MiB read
presented as `is_error` with the envelope-budget message, then a useful read of
`notes.txt`. Workspace unchanged, all host descendants stopped.

## Deterministic tests

- `cargo test -p agentfw --lib`: all pass, including `real_server::frames`
  (scanner versus strict parser, mutation sweep, exact envelope boundary,
  malformed / unterminated / endless / stalled frames) and
  `real_server::fault_tests` (exact large results, text and envelope refusals
  with continuation, concurrent and late cancelled frames, fail-closed cases,
  daemon size refusal), `server_profile` result budgets and `native` caps.
- `cargo clippy -p agentfw --all-targets -- -D warnings`, `cargo fmt --check`.
- `python3 -B -m unittest scripts/tests/test_large_results.py`.

## Separate finding

`read_multiple_files` with four or more files is refused by the accepted result
injection heuristic (`injection` low, `filesystem-profile-refuse-result-injection`)
at any size; two or three files are released. Reproduced with 2 KiB files. This
is detector behaviour owned by SOU-109 and is not changed here.

## Not claimed

No WSL2 run was performed in this environment; the reproducible WSL2 command is
in the guide and the report marks real WSL2 kernels separately. No Git-server
large-result run, live-model efficacy, arbitrary tools or unbounded streaming.
