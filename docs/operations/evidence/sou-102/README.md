# SOU-102 prepared classifier: acceptance on the original filesystem and Git MCP servers

Driver: `scripts/verify-sou102-prepared-classifier.py` (Linux x86-64). It runs the real
collector and daemon with the installed `rule-package` classifier and
`AGENTFW_CLASSIFIER_PREPARE=1` in front of an original pinned server, selected with
`--server filesystem|git`:

- filesystem: `@modelcontextprotocol/server-filesystem` 2026.8.31 (Node v22.22.0, locked npm
  packages, bubblewrap);
- git: `mcp-server-git` 2026.10.10 (Python 3.11.14 standalone, hash-locked packages, Git 2.51.2,
  bubblewrap 0.13.1, the `agentfw-git-sandbox` launcher).

Effects are witnessed by a kernel syscall trace of the original server, not by collector or
daemon logging: successful read-only opens of the exact synthetic file (filesystem) or the
exact `execve` of the pinned `git diff-tree <commit> --root -p` (Git). The raw traces are not
exported; `*.witness.json` hold only the matching lines.

```
python3 scripts/verify-sou102-prepared-classifier.py --run --server filesystem --agentfw <agentfw> \
  --node <node> --npm <npm> --bwrap <bwrap> --strace <strace> --python <python3> --output <new dir> --rounds 10
python3 scripts/verify-sou102-prepared-classifier.py --run --server git --agentfw <agentfw> --git <git> \
  --git-launcher <agentfw-git-sandbox> --bwrap <bwrap> --strace <strace> --python <python3> \
  --output <new dir> --rounds 10
```

## Result of the recorded runs (`filesystem/report.json`, `git/report.json`, both `passed`)

The same 11 cases passed on both servers:

| Case | Observed |
| --- | --- |
| Ready before the first call | One `mcp_classifier_ready` event, `start_sequence` 1, naming the one running owned worker; no read and no classification before the first call |
| First useful call | Same worker process, no second preparation, exactly one witnessed effect |
| Continuation | Same worker, one more witnessed effect |
| Session isolation | A second collector owns a different worker; closing it leaves the first worker running |
| Killed worker | Replaced before the next dispatch; the call succeeded with a new pid and one witnessed effect |
| Hung worker (SIGSTOP) | That call refused (`classifier_error`, policy not reached) in about 1.43-1.45 s, zero witnessed effects, worker retired; the next call recovered |
| Altered package file and lost worker | Refused with `classifier_not_ready` in about 20-28 ms, zero witnessed effects, no worker started; after restoring the exact bytes the next call succeeded |
| Collector exits without a call | The prepared worker is reaped; zero effects |
| Altered package at startup | Collector exits non-zero before serving, `no longer verifies` in the error, nothing left behind, zero effects |

Forbidden executions in every refusal case: 0 (witness count unchanged, no dispatch event).

## Latency (10 rounds per mode and server, no tracing; cold and warm are separate figures)

| p50 / max, ms | Filesystem | Git |
| --- | --- | --- |
| Lazy mode, first call (includes worker start) | 607 / 717 | 652 / 771 |
| Prepared mode, first call after readiness | 24.7 / 27.3 | 36.8 / 52.5 |
| Warm call, lazy | 13.9 / 20.0 | 34.1 / 43.6 |
| Warm call, prepared | 16.4 / 22.5 | 34.8 / 59.6 |
| Prepared, collector spawn to readiness event | 1224 / 1334 | 1200 / 1349 |

The last row includes starting the (debug) collector process and verifying the package, not
only the worker start. Calls that had to replace a lost worker took 779 to 965 ms in the same
runs, inside the unchanged 2 s outer deadline. Zero failures in the latency rounds.

## Not demonstrated, and caveats

- Mismatched ready identity and a late reply are not demonstrated against the installed
  package: its bytes are immutable, so no honest worker can be made to lie. They stay covered
  at worker level by `crates/agentfw/tests/classifier_runtime*.rs`.
- The frozen installed classifier reads `git_show` as a read but leaves `git_status`,
  `git_log` and the diff tools unknown (they are refused by policy), so `git_show` is the
  only useful Git call here. The classifier bytes are unchanged.
- One Linux container, debug build, one run per server; numbers are not a guarantee.
- Container deviations, none of which changes a deadline or the collector code:
  - the container reaches the network only through a proxy, so `npm ci` ran through a wrapper
    that adds the proxy settings, and pip got them from `/etc/pip.conf`; locked packages are
    unchanged and their hashes are checked by the installers;
  - the Git binary was built from the GitHub tag `v2.51.2` with the workflow's make options,
    because kernel.org is not reachable there; the profile's pinned tarball digest therefore was
    not the build input. The built binary's digest is in the report;
  - bubblewrap 0.13.1 was built from the pinned release tarball (digest verified), and
    `libtcl8.6`/`libtk8.6` were installed so the installer's ELF dependency check passes.
- Source: git tree `0817cff125b2d4868e5f62c02c0a1237b0009ddf` of the candidate checkout, clean,
  with the driver included. The recorded commit id belongs to a scratch checkout and is not
  a repository commit.
- Earlier attempts failed and their directories were not archived: the first filesystem
  attempt could not reach the npm registry (no proxy settings); three stopped on bugs of the
  driver itself (child processes of a blocking-pool thread were not listed; a check looked at
  a process that had already exited by design); the first Git attempt stopped at the
  installer's ELF dependency check (missing Tcl/Tk libraries). A filesystem run on an
  uncommitted driver also passed before the clean runs were recorded. None of these touched
  the collector code.
