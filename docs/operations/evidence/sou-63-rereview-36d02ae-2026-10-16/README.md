# SOU-63 adversarial re-review: 36d02ae

VERDICT: REQUEST CHANGES — four P1 findings and one P2 finding, reproduced by seven additional router-level witnesses.

Exact source: `36d02ae4eed49ed6fa9aa63524d3d9b4cfa182d4`.
All six witnesses from the 8dd0ee2 review now pass. The findings below cover incomplete authority validation and lifecycle paths beyond those individual witnesses.

## P1 — Changing hook agent_id bypasses the authenticated relation

Location: `crates/agentfw/src/native.rs:483-506`.

Bind reader to parent with only read_document. A Bash PreToolUse hook naming reader without parent_id is correctly resolved and denied. Change only agent_id to unregistered-impostor: resolution falls through to raw request identity with parent=None; the same protected request returns `{}`. The active verified host binding does not constrain unknown claims. Resolve identities from a verified binding and refuse unknown/mismatched delegated identities; preserve legacy behavior only in an explicitly separate unsupported/unbound mode. Do not choose an arbitrary collector when an omitted identity is ambiguous.

Witness: `review36_unknown_hook_agent_must_not_bypass_binding`.

## P1 — Missing authoritative parent state silently widens delegation

Locations: `native.rs:1036-1071`, `native.rs:1106-1114`, `native.rs:1140-1150`.

Three router-level reproductions:

- A signed child names nonexistent-parent. There is no parent session or firewall grant; session_start nevertheless registers the child via set_root and its delete_document call returns allow/release=true.
- A live parent has send_email but granted_resources=None. Its own external mail call is correctly denied because destination authority is unprovable. A child names that parent, supplies attacker.invalid as its own resource grant, and the same mail call returns allow/release=true. The resource check runs only when the parent's optional resource list is Some.
- A parent has send_email scoped to internal.corp. Child delegation to attacker.invalid is initially refused. End the parent through native session_end, then repeat the delegation: it is accepted and the outside mail call returns allow/release=true. The native parent record is gone but its host-session firewall tool grant survives. The fallback validates only tools, losing resource scope.

A valid child signature does not establish a subset of the actual parent's current authority. Use one authoritative parent binding containing tools, resources and lifecycle validity; require it before mutation. Unknown/missing/unprovable state must not become an unrestricted parent or a new root. If grants intentionally survive a transport disconnect, retain the complete validated scope and explicit lifetime rather than a tool-only record.

Witnesses: `review36_missing_parent_must_not_register_child_as_root`, `review36_unknown_parent_scope_must_not_become_proven_child_scope`, `review36_parent_end_must_not_drop_resource_constraints`.

## P1 — Expired native authority still authorizes hooks

Location: `native.rs:483-499`.

Create a parent and a child with a signed 500 ms grant including Bash and read_document. Before expiry the benign Bash hook is usable. After 550 ms the native read_document call correctly returns native_child_authority_expired. The same child's hook still resolves to the registered agent and returns `{}` instead of deny. resolve_hook_identity never checks authority_expires_at_ms, and hook traffic does not run native session pruning.

Validate the same expiry/revocation/lifecycle constraints on hook resolution as on native calls, with a fail-closed result for expired delegated authority. Expired entries must not fall through to legacy unbound identity.

Witness: `review36_expired_child_authority_must_not_authorize_hooks`.

## P1 — Identity-conflicting PostToolUse silently loses shared history

Location: `crates/agentfw/src/handlers.rs:696-708`.

For a known bound child, submit PostToolUse containing untrusted WebFetch output and a mismatched parent_id. The new identity error branch returns before event inspection, span retention, audit and provenance loss handling. The host ends with taint_len=0 and provenance_incomplete=false. A PostToolUse permissionDecision cannot undo an already completed tool result; discarding it without a sticky loss marker allows later collectors to receive weaker policy decisions.

Treat identity-conflicting/uninspectable consumed results as lost shared provenance. Mark the verified host's history incomplete before returning, and audit the refusal/loss without trusting the payload's parent claim. Keep PreToolUse blocking separate from retrospective result handling.

Witness: `review36_conflicting_posttool_identity_must_mark_history_loss`.

## P2 — Valid destination narrowing is rejected

Location: `native.rs:1051-1059`.

A parent has send_email scoped to internal.corp. Delegate the same tool to a child scoped only to alice@internal.corp: session_start returns 409/native_child_authority_escalation. The containment check supports equality and filesystem Path::starts_with only, although admission supports domain/mailbox and host/exact-URL scopes. Legitimate domain-to-mailbox and host-to-URL narrowing must use typed canonical destination containment, without requiring a broader grant.

Witness: `review36_legitimate_mailbox_narrowing_must_be_usable`.

## Independent verification

- Original source: 92 native endpoint, 13 hook endpoint and 280 library tests pass, including all six review8dd witnesses and lock-order witness.
- Both SOU-63 real-process stdio tests pass, including withheld backend execution assertions.
- cargo clippy --offline --all-targets -- -D warnings passes.
- cargo fmt --all --check passes.
- All seven review36 witnesses fail with the specific assertions above.
- Full workspace tests, protection_status and the other 67 MCP admission tests were not independently rerun.
- Target-controlled builds/tests ran only in an exported source copy, with writes restricted to /private/tmp/sou63-review. External networking was denied. Socket-dependent baseline and real-process tests had loopback-only access; independent witnesses had all networking denied.
- No product code was modified. Only this evidence directory was added to the workspace.

## Reproduction

Apply reviewer-witnesses.patch to a disposable checkout of this exact commit:

```sh
cargo test --offline -p agentfw --test native_endpoint review36 -- --nocapture
```

The patch reuses the committed review8dd_start and Fixture helpers. All identities, destinations, content and keys are synthetic fixtures; no external service is needed.
