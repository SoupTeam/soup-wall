# SOU-77 macOS Agent self-test evidence (2026-10-17)

Clean-directory demonstration of [`agentfw self-test`](../SELF_TEST.md) on native macOS Darwin with
selected installed runtime assets, independent prevention witnesses, and verified process cleanup.
No live model, provider account, network destination, real credentials or sealed data was used. Phase 4 stays open.

## Host and runtime environment

- Host: Apple Silicon (`arm64`), Darwin Kernel Version 25.3.0 (macOS Darwin 25)
- Toolchain: rustc 1.99.0, cargo 1.99.0 (Homebrew)
- Python: system Python 3.9.6 (`/usr/bin/python3`)
- Base commit: `main` `b53620db96209b3298fa11e3c399de5db6c83fe7` (SOU-67 merge)

## Source and binary assets

| File | SHA-256 |
|---|---|
| `crates/agentfw/src/self_test/mod.rs` | `8b1170cb98cbe437fb33569cd03af9b762bb276ba7f3e5aaef7aa9e160196b95` |
| `crates/agentfw/src/self_test/unix.rs` | `a8906f7086e6a79f2708caa5f2052d7986ad16f292ac3f6b18b2cd44322ccdb9` |
| `crates/agentfw/src/self_test/fixture.rs` | `535431e670d9162b0755b6bd5bbaaed43bbef0cd26cd1e38c46535bf08dc71ec` |
| `crates/agentfw/tests/self_test.rs` | `cc22bd836d04d0c7839ea65804dd1d72fd7f1f97623bb3970927ba32a6a1403d` |
| Built binary `agentfw` (release) | `c070a10397203cf03f869f5ba7f89f8d274fa78ce3865dd4f768bcf281780461` |
| Classifier script `rule_baseline.py` | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |

## Clean-directory run

The command ran from an isolated directory outside the repository checkout,
with the report written to a separate output directory and the system temporary directory
as the workspace parent:

```sh
cd <demo>/clean
<demo>/opt/soup-wall/bin/agentfw self-test \
  --agent <demo>/opt/soup-wall/bin/agentfw \
  --classifier rule-baseline \
  --classifier-script <demo>/opt/soup-wall/classifier/rule_baseline.py \
  --classifier-sha256 d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd \
  --classifier-python /usr/bin/python3 \
  --report <demo>/out/self-test-report.json
```

Result: **passed, exit 0**, 1.31 s total ([report](sou77/self-test-report.json), [console](sou77/stdout.txt)).
Profile: `macos-stdio-mcp-admission-v1` (`os: macos`, `arch: aarch64`).

| Scenario | Witnessed |
|---|---|
| `allowed_read` | Exact 54 expected bytes; 1 MCP child execution with original frame; result bytes unchanged; 0 deliveries |
| `adversarial_result` | 1 execution; result withheld (`ask-injection-in-result`); marker never reached the client |
| `protected_send_refused` | Refused (`deny-secret-egress`, native audit `deny`); 0 MCP child executions, 0 receiver connections |
| `useful_read_after_refusal` | Exact 55 expected bytes; 1 execution |
| `daemon_loss` | Owned daemon killed; collector closed; 0 executions, 0 receiver connections |

Classifier receipts show `rule-baseline/python`, the pinned revision and `policy: reached`.
The configured block confirms daemon PID authenticated, mode `enforcing`, registry `sw-self-test-fixture-v1`
(2 tools), and identical binary SHA-256 to the tested Agent.

## Verified process cleanup

Cleanup outcome from report:
- `collector`: `reaped: true`, `process_group_empty: true`
- `daemon`: `reaped: true`, `process_group_empty: true`
- `receiver`: `socket_closed: true`
- `workspace`: `removed`
- Process audit: verified via `/bin/ps -axww -o command=` that no running process references the workspace path.

## Actionable incomplete

Running the same command with a mismatched `--classifier-sha256` stopped before launching any processes:
**incomplete, exit 4**, all 5 scenarios `unavailable`, with explanation
`the classifier source does not match --classifier-sha256 (wrong revision)`
([report](sou77/self-test-wrong-revision.json), [console](sou77/stdout-wrong.txt)).

## Local check suite

| Command | Result |
|---|---|
| `cargo test --locked -p agentfw --lib self_test` | 10 passed (0.08 s) |
| `cargo test --locked -p agentfw --test self_test` | 7 passed (11.77 s) |
| `cargo test --locked -p agentfw --test lifecycle -- --test-threads=1` | 5 passed (67.77 s) |
| `cargo clippy --workspace --all-features --all-targets --locked -- -D warnings` | clean (zero warnings) |
| `cargo fmt --all -- --check` | clean (zero diff) |

## Limits

- Scripted client frames: not Claude Code, model context or live-model effectiveness.
- Bundled fixture server with two tools; other servers require their own reviewed registry.
- macOS and Linux profiles: other operating systems report `unsupported` (exit 5).

## Reviewer follow-up

The required native self-test integration suite now fails if Python is unavailable; missing prerequisites cannot become a successful early return. The retained native runtime evidence is macOS ARM64. Intel x86-64 remains conditional until a corresponding native positive acceptance is retained; compilation alone is insufficient. The runtime implementation and release binary above are unchanged by this test/documentation follow-up.
