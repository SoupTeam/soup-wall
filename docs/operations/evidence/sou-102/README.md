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

## Final candidate evidence (`final/filesystem/report.json`, `final/git/report.json`, both `passed`)

Both runs executed the driver and binaries from a clean checkout of repository commit
`3745b24eda71e03d3b13d7dfd3883510ad043bf7` (tree `2a0e0677814e3405fde2a4f7345d0d206f0ffb38`), the
branch head after main (including #212) was integrated;
`source_before` and `source_after` in each report name that commit and tree, `dirty: false`.
This evidence is committed afterwards, so the reports bind to the parent of the commit that adds
them. The reports under `filesystem/` and `git/` (next section) are earlier development
evidence and are kept as they were.

Inputs: the collector built from that commit (`agentfw` sha256 `1703a2fe3dfe9d8f…dfba47f`),
bubblewrap 0.13.1 built from the pinned release tarball, and, for Git, **the accepted source
archive**: `git-2.51.2.tar.xz` (sha256
`233d7143a2d58e60755eee9b76f559ec73ea2b3c297f5b503162ace95966b4e3`, the pin in
`profiles/mcp/git-readonly-v1/upstream-identity.json`) was supplied locally, its digest checked, and
built with `make -j4 NO_CURL=YesPlease NO_EXPAT=YesPlease NO_TCLTK=YesPlease NO_GETTEXT=YesPlease
NO_OPENSSL=YesPlease git`. The resulting binary (`git version 2.51.2`) has sha256
`bdbe57ea5957de12eedf3414ef7295ed08ebb1c270e43af7b91f4c4bde1b9ca3`, recorded in the Git report.

The same 11 cases passed on both servers (descriptions in the table of the next section):
ready before the first call, first useful call, continuation, session isolation, killed worker,
hung worker, recovery after the hang, altered package with lost worker, recovery after restore,
no call made (worker reaped), startup failure. Zero forbidden executions in every refusal case.

| p50 / max, ms (10 rounds, no tracing) | Filesystem | Git |
| --- | --- | --- |
| Lazy mode, first call (includes worker start) | 623.4 / 803.6 | 583.0 / 783.9 |
| Prepared mode, first call after readiness | 25.5 / 32.2 | 34.8 / 38.6 |
| Warm call, lazy | 20.6 / 25.3 | 31.8 / 44.9 |
| Warm call, prepared | 17.8 / 27.3 | 30.7 / 43.7 |
| Prepared, collector spawn to readiness event | 1120 / 1192 | 1101 / 1266 |

Refusals: hung worker 1438 ms (filesystem) and 1428 ms (Git), altered package with lost worker
25.4 and 25.9 ms. Calls that replaced a lost worker took 650 to 865 ms (filesystem) and 793 to
959 ms (Git), inside the unchanged 2 s outer deadline.

Mismatched ready identity and bad replies are worker-level evidence, kept apart from these
installed-runtime runs: they are exercised by the named tests
`classifier_runtime::worker::ready_tests::*` (a test-only bootstrap seam in
`crates/agentfw/src/classifier_runtime/worker.rs`; package verification and production behaviour are
unchanged). They cover a wrong classifier digest, a wrong protocol version, `ready: false`, an
unknown field and a malformed ready frame, and a reply with a wrong id, a different input digest, a
wrong protocol version, an unknown field or a malformed body; each ready case also checks that no readiness is recorded, and every case checks that no worker is
retained and the injected process is gone. A control case proves the
injected worker is accepted when it answers correctly. No frozen package bytes are altered.

Remaining caveats of these runs: one Linux container, debug build, one run per server; the
container reaches the network only through a proxy, so `npm ci` ran through a wrapper that adds the
proxy settings and pip got them from `/etc/pip.conf` (locked packages unchanged, hashes checked by
the installers); `libtcl8.6`/`libtk8.6` were installed so the installer's ELF dependency check
passes; Git coverage is `git_show` only, as the frozen classifier leaves the other Git tools unknown.
Some attempts stopped before any case because the container's proxy settings (the npm wrapper
and `/etc/pip.conf`; the proxy port changes between sessions) were stale, and a leftover temporary
directory blocked one retry; none touched the collector. An earlier pair of runs on commit
`9ee602a` (before #212 was integrated) also passed 11 of 11 on both servers; it is superseded by
the runs above and was not archived.

## Historical development runs (`filesystem/report.json`, `git/report.json`, both `passed`)

These were taken on a scratch checkout before the final runs above. They are kept as development
evidence and are not the candidate qualification.

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

- (Historical note, superseded by `classifier_runtime::worker::ready_tests` described above.)
  Mismatched ready identity and a late reply are not demonstrated against the installed
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
