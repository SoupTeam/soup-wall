# Constrained create-file CI repair and complete OS-failure proof

SOU-54, 2026-10-15. This supersedes the current-candidate portion of the
[initial verification](MCP_CREATE_FILE_2026-10-15.md); the earlier raw archive and
original red witnesses remain unchanged.

Exact clean runtime/build source: `dbd7a097f4da79341aab5fcf49b32598d523bb41`.
The subsequent delivery adds only documentation/evidence. Source and binary
identities stayed unchanged during both complete drivers.

[Operator commands](../MCP_CREATE_FILE.md),
[complete source/configuration and outcome manifest](MCP_CREATE_FILE_2026-10-15.followup.json),
[raw actual-process evidence](MCP_CREATE_FILE_2026-10-15.followup.raw.tar.gz),
[archive member verification](MCP_CREATE_FILE_2026-10-15.followup.raw-manifest.json).

## Repeated complete outcomes

| Check | Result |
| --- | --- |
| Actual stdio MCP matrix | 26 passed, 0 failed, 0 skipped |
| Actual native HTTP/stdio races and OS partial write | 9 passed, 0 failed, 0 skipped |
| Linux Agent unit tests | 241 passed, 0 failed, 0 ignored |
| Linux native endpoint tests | 39 passed, 0 failed, 0 ignored |
| Strict Linux Agent/all-target Clippy | passed |
| Final independent Python evidence controls | 26 passed, 0 failed |
| Full Python script suite | 538 run, 512 passed, 26 existing environment skips |

Linux remained aarch64, kernel `6.12.76-linuxkit`, overlayfs, Rust 1.98.1 and
Python 3.11.2, under UID/GID 65532 with zero effective capabilities,
`NoNewPrivs: 1`, seccomp and `--network=none`. Actual loopback traffic remained
inside the disposable container. All owned private fixtures and the container
were removed. The image, three native binary digests, full input manifest and
per-case configuration hashes are retained.

Agent SHA-256:
`8a248e7db45b5f30e6d1c75134ba387a336b83634e45a46c9569015afcad664a`.
Image ID:
`sha256:c1923107133e287919128614d6ce51ab33920d7a75fd7575ae6cb28db215d658`.

The 26-case matrix again had zero false interruptions among four deliberately
useful permitted creates. Its 95 observed create calls had p50 0.628 ms,
p95 93.185583 ms and maximum 330.007083 ms. These debug-build client-to-response
samples include fast pre-execution refusals and process startup effects; they
are not an isolated executor overhead or production latency objective. The
single outlier remains in raw evidence, without smoothing or a hidden retry.

## Real partial-write error at the MCP execution boundary

The ninth case uses a small Linux fixture launcher, which sets only its owned
collector's soft/hard `RLIMIT_FSIZE` to **2,048 bytes** and ignores `SIGXFSZ`
before exec. The real rule baseline classifies the original 4,096-byte ASCII
content. The real daemon provides ordinary native Allow. No production test hook
or invented admission receipt is used.

The allowed executor accepts 2,048 bytes into its anonymous staging inode, then
the OS rejects the remaining write. Both the real broker event and inspected,
correlated MCP error report:

```json
{"success":false,"created":false,"committed":false,"error":"stage_write_failed","staged_bytes":2048,"committed_bytes":0}
```

The error completion itself passes actual native result inspection and release.
Independent workspace/outside trees stay identical: no destination or named
staging file appears. The discovery child receives no tools/call. A useful read
then succeeds in the **same native session**, and child/collector EOF is clean.
This is an executed failing operation with honest staged-byte accounting, not a
pre-execution Deny and not proof that no syscall ran.

The parent drains collector stderr through a bounded pipe into its own regular
log. This preserves diagnostics independently of the child's file-size limit;
EOF, successful drain and thread join are required. The launcher digest, actual
OS-limit/signal record, raw receipt and all witnesses are retained. This closes
the earlier limitation that partial-write failure had only native unit evidence.
The original eight race cases all passed again, including one complete winner
under concurrent creation and refusal before execution for held-allow overlap.

## Initial hosted CI failure and repair

The first [all-features job](https://github.com/SoupTeam/soup-wall/actions/runs/38701243354/job/116309675452?pr=122)
on head `8cdc8da` failed strict Linux Clippy at the three root-identity checks in
`mcp/create_file.rs`: `needless_borrows_for_generic_args`. macOS did not compile
that Linux-only body. This was an actual required-check failure, not a passing
runtime result or an unrelated test.

Repair `7383a41` passes the Copy closure directly rather than by unnecessary
reference. No warning allowance, weakened root check, skipped case or
confirmation change was added. All 34 existing actual-process cases and the
Linux native suites were repeated on that exact repair first; the final source
above repeats them again and adds the ninth OS-failure case. The Linux builder
now explicitly runs warnings-denied Agent/all-target Clippy before building the
selected binaries. Formatting and workflow actionlint also passed.

The older report describes two preliminary Docker failure classes, not a count
of every retry. Those setup errors did not reach runtime tests. The final retained
Dockerfile and test-specific ignore file build from a clean owned Git archive.

Full final-head hosted CI and independent approving review still gate source
acceptance. The task remains **Review**, with no main merge or Done claim. The
Linux-only, exact-target, direct-root-child and 4,096-byte bounds, same-UID root
relocation limitation, unsupported operations and honest post-commit result
withholding semantics remain those documented in the operator contract. SOU-48
approval storage/redemption/endpoints/CLI and Console recovery remain unchanged.

Raw archive SHA-256:
`25247cc42c527ff034120a838bbeee2561b5600ecbd3fbfa144ddca73525d14e`.
All 16 member byte counts and SHA-256 values were independently verified.
Runtime input manifest SHA-256:
`369bf527e590701796d2c0ea202f7e63d3bab02ffbeae6865746e4747914582f`.
