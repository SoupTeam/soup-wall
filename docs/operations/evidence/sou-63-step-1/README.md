# SOU-63 Step 1 validation

Implemented the standalone child authority grant API and exports. Tokens are
unpadded base64url JSON with strict field deserialization. HMAC-SHA256 key
derivation uses the daemon token as key and the specified domain as message.
Signatures cover the contract, session, server, counted tool list, timestamps,
and nonce with explicit field lengths. Comparison uses `ConstantTimeEq`.

Expiry is exclusive; future issuance tolerates five seconds of clock skew,
matching the existing approval grants. Expiry addition saturates on overflow.
This synchronous, stateless module has no storage, asynchronous cancellation
points, or nonce consumption; tool enforcement and grant delivery remain caller
responsibilities for later steps.

Validation on 2026-10-16:

- `cargo test -p agentfw --lib child_authority`: passed all 10 tests.
- `cargo clippy --all-targets -- -D warnings`: passed, zero warnings.
- `cargo fmt --check`: passed.
- `git diff --check`: passed.
- `cargo test -p agentfw --lib`: 266 passed, 4 failed because the sandbox denies
  binding local ports (`PermissionDenied`, `Operation not permitted`).
- `cargo test`: stopped at the same four agentfw library tests for the same
  environmental reason; subsequent test binaries were not executed.

The blocked existing tests are:

- `mcp::admission::resource_receipt_tests::missing_or_changed_resource_hash_and_old_contract_are_refused_over_http`
- `sandbox::tests::guarded_network_fetch_refuses_unknown_hosts_before_proxy_io`
- `sandbox::tests::guarded_network_fetch_requires_a_policy_egress_allowlist`
- `sandbox::tests::guarded_network_fetch_uses_the_proxy_and_bounds_the_response`

Adjacent logs retain command output. The new tests cover authentication of every
claim, wrong keys, host/server spoofing, invalid contracts, malformed JSON and
base64, duplicate/unknown fields, invalid time intervals, expiry, future skew,
overflow, field-boundary collisions, concurrent verification, error reasons,
and an independently generated key-derivation vector.
