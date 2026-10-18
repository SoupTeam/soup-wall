# SOU-88 resource Ask confirmation evidence

## Review follow-up

The review of `5a7a66f4e7cd66ad27bf9b0574b7bd1c68afa7c8` accepted the
hard-floor, ambiguous-classification, strict platform and terminal-invalidation
fixes. The remaining blocker was production read/GET execution acceptance.

Earlier descriptions of `resource_approval_witness.rs` as filesystem/network
execution proof were incorrect. Those tests invoke the native authorization
router only. The test-side simulated create was removed; the tests now explicitly
name single-use **authorization** rather than execution. No historical API
receipt is evidence of an actual read or HTTPS request.

## Execution witnesses

`crates/agentfw/tests/support/resource_approval_execution.rs`, included by
`mcp_admission.rs` only on Linux, runs two acceptance tests:

- `sou88_read_document_real_executor_approval_controls`
- `sou88_https_get_real_tls_receiver_approval_controls`

Each uses a real `agentfw mcp --native-admission` subprocess, its real discovery
child, production rule-baseline classifier, authenticated production Axum native
router, and the production constrained resource executor. The router is hosted
in the test process; this is not an installed service/restart or model/UI test.
The Ask policy and resources belong to disposable fixture directories.

Each operation exercises six scenarios: rejection, actual TTL expiration,
mutation of approved arguments in transport, cancellation while pending,
duplicate request while pending, and approval. Before approval, all scenarios
assert no protected read and no target connection. Failed controls assert no
protected effect. The successful call releases the actual document/receiver
body, duplicate operator approval fails, an actual captured redemption request
is replayed against the router and refused as spent, and the repeated MCP
request ID closes without another effect.

After rejection, expiration and mutation, a different request in the same
collector session must obtain a new approval and complete useful work.
Cancellation and overlapping/duplicate input deliberately close the collector;
no promise to resume those closed sessions is made. All scenarios assert zero
child tool-call dispatches.

### Independent observations

- Read: Linux `inotify` watches `IN_ACCESS` on the protected file. The test does
  not open/read it while watching. Metadata checks and O_PATH pinning are not
  counted as a protected byte read. The successful reply must contain the exact
  original file contents; refusal/replay must produce no new access event.
- GET: a separate Python process owns a local TLS socket and append-only ledger
  of accepted connections, TLS handshakes and HTTP requests. Each approval
  produces exactly one connection and `GET /document?item=7`; refused controls
  produce zero connections/requests. The result must contain the real receiver
  document. This reuses the existing SOU-56 owned receiver and disposable CA,
  retaining normal hostname/CA/expiry validation. The private endpoint exception
  pins only the owned loopback address and port; production network rules are
  unchanged.
- Argument mutation changes only arguments before the authentic router sees
  redemption. The fixture never manufactures Allow, resource bindings, or
  executor output. A fresh request subsequently succeeds with unchanged policy.

The existing collector create-file acceptance remains in
`sou88_resource_create_ask_operator_approval_runs_once_and_reject_zero_execution`.
It verifies production creation and exact contents, independently of the API
single-use authorization suite.

## Reproduction and retained output

On Linux with Python 3, OpenSSL and the locked Rust dependencies:

```sh
cargo test --locked -p agentfw --test mcp_admission sou88 -- --nocapture
cargo test --locked -p agentfw --test resource_approval_witness -- --nocapture
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

The `Constrained MCP HTTPS GET` workflow runs both suites on the exact PR head
and retains `sou88-execution.log` and `sou88-authorization.log` alongside its
existing source, toolchain and binary identities. Each completed execution
scenario emits `SOU88_EXECUTION operation=... scenario=... passed=true` only after
its effect and refusal assertions pass.

Local macOS checks cover the platform refusal, existing collector compatibility,
formatting and warnings-denied Clippy. They cannot establish the Linux-only
positive execution cases. Linux CI results and final source identity are recorded
below after execution; adding a witness alone is not a passing result.

## Local verification (macOS, 2026-10-18)

Isolated source copy, repository read-only to target processes, no external
network, only loopback fixture traffic and disposable scratch writes allowed.

- `cargo test --offline --locked --workspace`: exit 0; **1,478 passed, 0 failed,
  11 ignored**, across 65 reported suites. Ignored/unsupported platform cases
  are not claimed as passing Linux execution evidence.
- `cargo clippy --offline --locked --all-targets -- -D warnings`: exit 0.
- `cargo fmt --all -- --check`: exit 0.
- Existing SOU-88 collector tests: 2 passed; native authorization suite on macOS:
  the single explicit non-Linux platform-refusal test passed.

Initial local runs exposed the stale non-Linux-positive unit expectation (fixed
in this change), then the sandbox's refusal of `/bin/ps` used by existing process
cleanup witnesses. The final passing run allowed only that read-only system
helper outside the child sandbox while retaining source-write and external
network restrictions. Those earlier failures are not represented as passes.

Linux execution acceptance is pending the hosted run of this follow-up.
