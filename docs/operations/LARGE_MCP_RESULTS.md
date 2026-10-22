# Large original-server results: limits and recovery

This guide covers result size handling for the selected original-server
profiles (`sw-mcp/filesystem-readonly/1` and `sw-mcp/git-readonly/1`; Git
results use the same text and envelope budgets, qualified here with the
filesystem server). It changes result transport only. Tools, arguments, classifier, policy and
detectors are unchanged.

## Problem on accepted main

Reproduced on main `4828cf3` with the pinned original filesystem server and
owned synthetic files:

| Read | Before | Cause |
| --- | --- | --- |
| `read_text_file` 16,383 and 16,384 bytes | released | |
| 16,385 bytes, 20, 60 and 120 KiB | withheld as "Unsupported MCP result" | `structuredContent` was validated with the 16 KiB argument string default |
| 128 KiB, 2 MiB, 20 x 20 KiB `read_multiple_files` | session ended ("MCP frame exceeds admission limit") | the whole response line was limited to 256 KiB and an over-limit line was fatal |

The original server sends the file text twice: in `content[0].text` and in
`structuredContent.content`. A 120 KiB file is therefore a frame of about
245 KiB, before JSON escaping.

## Budgets

| Limit | Value | Where | Applies to |
| --- | --- | --- | --- |
| Result text | 262,144 decoded UTF-8 bytes | `input::RESULT_STRING_BYTES`, `server_profile::RESULT_TEXT_BYTES` | each `content` text block and each `structuredContent` string without an explicit `maxLength` |
| Response envelope | 1,048,576 bytes, newline included | `server_profile::RESULT_FRAME_BYTES` | one complete server response line |
| Drain | 16 MiB and 10 seconds | `RESULT_DRAIN_BYTES`, `RESULT_DRAIN_TIME` | discarding one oversized frame |
| Native result content | 1,048,576 bytes | `native::MAX_MCP_RESULT_CONTENT` | `result` events with `mcp_host` delivery only |
| Native result body | 2,424,832 bytes | `native::MAX_MCP_RESULT_BODY` | the same events; the frame re-escaped (at most 2x) plus arguments |
| Recorder | `max_record_bytes` (default 262,144) | daemon `config.yaml` | each decoded text of a selected result |

Unchanged: arguments keep the 16 KiB default string budget and explicit schema
bounds; client frames, discovery, `MAX_CONTENT` for all other native events,
the registry limit and provenance `max_input_bytes` (262,144) are not raised.
Explicit `maxLength` values in an original output schema still apply, with the
same type checks. Nothing is truncated, dropped, skipped, split or retried.

Why these numbers: one maximal text appears twice, so 2 x 256 KiB plus ordinary
escaping fits in 1 MiB. Text that is mostly quotes, backslashes or control
characters can exceed the envelope before the text budget; that is refused as an
envelope overflow. The text budget equals the default recorder cap and the
provenance input limit, so a supported result never needs either raised.

Memory: the collector buffers at most one frame of 1 MiB from the server. An
oversized frame is never buffered: a constant-memory JSON scanner validates and
discards it. With 8 active calls the worst case is about 8 x (frame + parsed
value + daemon request body), roughly 40 MiB. Measured growth with 8 concurrent
120 KiB reads plus one 2 MiB response: 6 to 9 MiB.

## What the host sees

| Situation | Host reply (same JSON-RPC id) | Session |
| --- | --- | --- |
| Text and frame within budget | the exact original frame, both channels | continues |
| A text over 262,144 bytes | error `-32603`: "MCP result withheld: a result text exceeds the 262144-byte per-result budget; the original call may have executed" | continues |
| A well-formed response over 1 MiB | error `-32603`: "MCP result withheld: the response frame exceeds the 1048576-byte envelope budget; the original call may have executed" | continues |
| A decoded text over the daemon `max_record_bytes` | `isError` result "Soup Wall withheld MCP result (native_record_over_cap)" | continues |
| The daemon refuses the request size (lower `max_body_bytes`) | error `-32603` naming `native_body_over_cap` | continues |
| Injection or other policy refusal | `isError` result with the rule, as before | continues |

Every refusal spends the call's own grant with a receipt. The original call
may already have executed: the server read the file before the response was
refused. Soup Wall never treats that as zero execution and never retries it.

An oversized frame is bound to a call only when the whole frame is valid JSON
with exactly `jsonrpc` `"2.0"`, a scalar `id`, and one of `result` or `error`
at the top level, and that `id` is an outstanding admitted call. The `id` is
never taken from incomplete JSON. A late frame for a cancelled call is
discarded like any late result.

These cases end the session (fail closed) with a fixed relay code:

| Case | Code |
| --- | --- |
| Malformed bytes in an oversized frame | `result_frame_malformed` |
| No usable top-level `id`, a notification, or extra members | `result_frame_uncorrelated` |
| Oversized frame longer than 16 MiB | `result_drain_bytes` |
| Oversized frame not finished within 10 seconds | `result_drain_time` |
| End of stream inside a frame | `server_frame_unterminated` |
| Oversized `initialize` or `tools/list` response | `control_frame_oversized` |
| Unknown or duplicate response id | `response_id_unbound` |

## Recovery

- After a budget refusal, keep working in the same session. Read a smaller
  file, or use `read_text_file` with `head` or `tail` to read part of a large
  one.
- `read_multiple_files` returns one text for all files, so the text budget
  applies to the total. Split the paths into smaller calls.
- `native_record_over_cap`: the daemon `max_record_bytes` is lower than the
  result text. Set it to at least 262,144 (the default and the result text
  budget) in the daemon `config.yaml` and restart the daemon. Inspection is
  never skipped to work around it.
- A fail-closed session: restart the MCP server connection in the host. Then
  check the collector log for `mcp_real_server_end` and the relay code.
- Collector stderr records each refusal as `mcp_real_result_withheld` with the
  call id, the limit name, the budget and the observed size. It never contains
  result bytes.

Known separate limit: `read_multiple_files` with four or more files is refused
by the accepted result injection heuristic at any size (`injection` finding,
rule `filesystem-profile-refuse-result-injection`); this is detector behaviour,
not a size limit.

## Qualification

`scripts/verify-large-results.py` runs the pinned original filesystem server
with an enforcing daemon, the accepted classifier and policy, and a syscall
witness. It covers exact results at 16,383 / 16,384 / 16,385 bytes, 20, 60 and
120 KiB, just below / at / above the text budget (ASCII and 4-byte UTF-8), an
escaped-text file, frames of exactly 1,048,575 / 1,048,576 / 1,048,577 bytes, a
3 x 20 KiB multi-read, a 20 x 20 KiB multi-read, a 2 MiB file, an injection at
the end of a 200 KiB file, a secret in a small and a large file, cancellation of
an oversized read, 8 concurrent 120 KiB reads plus one 2 MiB read, a daemon with
`max_record_bytes: 65536`, and genuine Claude Code 2.1.251 with the owned
scripted provider (large read, 2 MiB refusal, useful read). Every refusal is
followed by a useful read in the same session.

Linux (required; the filesystem CI job runs the same command):

```bash
python3 -B scripts/verify-large-results.py --run \
  --agentfw "$PWD/target/debug/agentfw" \
  --node /path/to/node-v22.22.0/bin/node --npm /path/to/node-v22.22.0/bin/npm \
  --bwrap /path/to/bubblewrap-0.13.1/bwrap --strace /usr/bin/strace \
  --claude /path/to/claude-host/node_modules/@anthropic-ai/claude-code-linux-x64/claude \
  --expected-commit "$(git rev-parse HEAD)" --output /tmp/large-results
```

WSL2 (Ubuntu 24.04, from a Linux-filesystem checkout such as `~/soup-wall`, not
`/mnt/c`): install the same pins as the filesystem CI job (official Node
22.22.0, bubblewrap 0.13.1 built with `--ro-bind-fd`, `strace`, the pinned
Claude Code host from `profiles/mcp/filesystem-readonly-v1/claude-host`), build
with `cargo build --locked -p agentfw --bins`, then run the command above.
The report records `platform.kind` as `wsl2` only when the kernel release is a
`microsoft-standard-WSL2` kernel; otherwise it is `linux`. Evidence from a
hosted Linux runner is never reported as WSL evidence.

Malformed, unterminated, endless and slow oversized frames cannot be produced by
the original server. They are covered by deterministic relay tests
(`real_server::frames` and `real_server::fault_tests`), which also cover
concurrent correlation, late cancelled frames and daemon size refusals.

Evidence: [Linux run, 2026-10-23](evidence/LARGE_RESULTS_2026-10-23.md).
