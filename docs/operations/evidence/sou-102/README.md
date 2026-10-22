# SOU-102 prepared classifier: acceptance on the original filesystem MCP server

Driver: `scripts/verify-sou102-prepared-classifier.py` (Linux x86-64). It runs the real
collector and daemon with the installed `rule-package` classifier and
`AGENTFW_CLASSIFIER_PREPARE=1` in front of the pinned original
`@modelcontextprotocol/server-filesystem` (Node v22.22.0, bubblewrap, locked npm packages).
Effects are witnessed by a kernel syscall trace of the original server (successful read-only
opens of the exact synthetic file), not by collector or daemon logging. The raw trace is not
exported; `*.witness.json` hold only the matching lines.

```
python3 scripts/verify-sou102-prepared-classifier.py --run --agentfw <agentfw> --node <node> \
  --npm <npm> --bwrap <bwrap> --strace <strace> --python <python3> --output <new dir> --rounds 10
```

## Result of the recorded run (`report.json`, status `passed`)

| Case | Observed |
| --- | --- |
| Ready before the first call | One `mcp_classifier_ready` event, `start_sequence` 1, naming the one running owned worker; no read and no classification before the first call |
| First useful call | Same worker process, no second preparation, exactly one witnessed read |
| Continuation | Same worker, one more witnessed read |
| Session isolation | A second collector owns a different worker; closing it leaves the first worker running |
| Killed worker | Replaced before the next dispatch; the call succeeded with a new pid and one witnessed read |
| Hung worker (SIGSTOP) | That call refused (`classifier_error`, policy not reached) in 1432 ms, zero witnessed reads, worker retired; the next call recovered |
| Altered package file and lost worker | Refused with `classifier_not_ready`, zero witnessed reads, no worker started; after restoring the exact bytes the next call succeeded |
| Collector exits without a call | The prepared worker is reaped; zero reads |
| Altered package at startup | Collector exits non-zero before serving, `no longer verifies` in the error, no worker left behind, zero reads |

Forbidden executions in every refusal case: 0 (witness count unchanged, no dispatch event).

## Latency (10 rounds per mode, no tracing; separate cold and warm figures)

| Measure | p50 | max |
| --- | --- | --- |
| Lazy mode, first call (includes worker start) | 588 ms | 617 ms |
| Prepared mode, first call after readiness | 22 ms | 31 ms |
| Warm call, lazy / prepared | 13.7 ms / 13.8 ms | 19.0 ms / 16.8 ms |
| Prepared, collector spawn to readiness event | 1060 ms | 1174 ms |

The last row includes starting the (debug) collector process and verifying the package, not
only the worker start. Calls that had to replace a lost worker took 703 to 787 ms in the same
run, inside the unchanged 2 s outer deadline. Zero failures in the latency rounds.

## Not demonstrated, and caveats

- Mismatched ready identity and a late reply are not demonstrated against the installed
  package: its bytes are immutable, so no honest worker can be made to lie. They stay covered
  at worker level by `crates/agentfw/tests/classifier_runtime*.rs`.
- The original Git MCP server was not run in this report.
- One Linux container, debug build, one run; numbers are not a guarantee. The container
  needed an npm wrapper that only adds the proxy settings (`HTTPS_PROXY`, CA bundle) to `npm ci`
  because the installer passes only `PATH` and `LANG`; the locked packages are unchanged.
- Source: git tree `3b4b61028a662c32c40e0757d64ed62b27f4fc46` of the candidate checkout, clean,
  with the driver included. The recorded commit id belongs to a scratch checkout and is not
  a repository commit.
- Earlier attempts of the driver failed and their directories were not archived: the first
  could not reach the npm registry (no proxy settings), the next three stopped on bugs of
  the driver itself (child processes of a blocking-pool thread were not listed; a check
  looked at a process that had already exited by design). None of them touched the collector
  code. The next run passed but with the driver still uncommitted (dirty tree), so it was
  repeated on the clean tree; this report is that clean run.
