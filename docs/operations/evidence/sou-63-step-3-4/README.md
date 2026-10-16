# SOU-63 Steps 3–4

Implemented collector host-session/child-authority configuration, startup binding,
CLI flags with environment fallback, and `child-authority mint` / `verify`.
Existing Steps 1–2 working-tree changes were preserved.

The CLI reads the existing native-token without creating or rotating credentials.
Mint uses the child-authority key derivation, current timestamp, random nonce,
and saturating seconds-to-milliseconds TTL conversion. Verification failures
return the grant API's static reason without printing the submitted token.

## Coverage

- CLI grant round trip with a comma-delimited tool grant.
- Missing native token does not create credentials.
- Expired, malformed, wrong-host, and wrong-server grants are refused.
- Actual stdio MCP result reaches host hook policy as MCP taint with server provenance.
- Explicit flags override environment bindings; environment fallback also covered.
- Invalid and wrong-server grants reject collector startup before server creation.
- Bound cancellation and concurrent calls withhold results and host provenance.
- Synthetic grant and native token must be absent from successful flow audit output.

## Verification (2026-10-16)

| Command | Result | Log |
| --- | --- | --- |
| `cargo test -p agentfw --test mcp_admission` | 67 passed, 0 failed | `mcp-admission.log` |
| `cargo test -p agentfw --test mcp_admission sou63_child_authority_cli_round_trip_and_refusals` | Passed | `child-authority-cli.log` |
| `cargo test -p agentfw --test native_endpoint` | 59 passed, 0 failed | `native-endpoint.log` |
| `cargo test --workspace` | All test suites passed, 0 failed | `workspace-tests.log` |
| `cargo clippy --all-targets -- -D warnings` | Passed, zero warnings | `clippy.log` |
| `cargo fmt --check` | Passed | `fmt.log` |

All integration, regression, and unit test suites across the workspace pass cleanly with zero warnings.
