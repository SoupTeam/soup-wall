# SOU-63 adversarial review — REQUEST CHANGES

Reviewed PR #146 exact head `554b32bdfcc7b694091f4398063af3773303839b` against the original Linear SOU-63 deliverables. Product sources were not changed. No messages, review comments, commits or pushes were sent.

## Independently reproduced blockers

1. **P1 — Host taint is not consulted by other collectors.** `native.rs:899-907` inspects calls against each collector's random native epoch. Host admission at `native.rs:1141-1158` is one-way. A result from server A taints `host`, but server B, bound to the same host with an authorized destructive tool, gets `allow` and an execution receipt when reusing that exact result text under a policy explicitly denying MCP-tainted destructive calls. Hook-to-MCP shares the same missing read path. Consult authenticated shared host history/incomplete floors while preserving exact per-invocation identities.
2. **P1 — Empty child tool scope grants everything.** `native.rs:860-862` skips containment when `granted_tools` is empty. A correctly signed empty grant authorizes `delete_document`; the CLI defaults `tools` to an empty vector. The shipped test `bound_trusted_result_keeps_registry_provenance_and_empty_grant_semantics` codifies this unsafe wildcard behavior despite documentation promising explicitly listed tools. An empty scope must grant nothing; any wildcard must be an explicit reviewed contract, with parent containment enforced.
3. **P1 — Grant expiry does not bound established authority.** `native.rs:758-804` verifies expiry only at session creation and discards the deadline. A 100 ms grant authorizes a fresh destructive call after 150 ms. Repeated activity refreshes the session idle timeout. Retain and check the authenticated absolute deadline on calls and result admission; define parent termination/revocation behavior and clean up pending authority safely.
4. **P1 — Unbound hook lifecycle can erase bound host history.** `handlers.rs:160-200` trusts hook payload session IDs with a shared hook bearer, without authenticating the host/agent/parent epoch. A normal hook `SessionEnd` clears `host` taint while its bound native child remains active. Validate the authenticated host lifecycle and prevent unrelated/reset events from clearing an active host's history.
5. **P1 — Required hook size/incomplete-history controls remain unimplemented.** `/hook` retains Axum's default 2 MiB extraction limit (`lib.rs:57`), while the configured default body cap is 8 MiB. The real router returns an accidental plain HTTP 413 for a protected PreToolUse just above 2 MiB. At a configured 1024-byte cap, an oversized PostToolUse returns `{}` at `handlers.rs:150-155` without marking shared history incomplete. Malformed/missing hook fields also return `{}`. These behaviors predate this PR but are explicitly assigned SOU-63 deliverable 4, so they block claiming the task complete. Implement bounded parsing with documented authenticated enforce dispositions and sticky shared incomplete-history floors.

## Additional directly visible blocker

6. **P1 — Partial collector binding silently downgrades to isolated legacy mode.** `mcp/admission.rs:2557-2571` sends a bound session only if both options are present; supplying only `--host-session` or only `--child-authority` starts an unbound session and proceeds to spawn the server. `main.rs:627-629` allows either partial CLI/environment configuration. Require both-or-neither; requests for authenticated mode must fail before spawn if incomplete. Also reject binding flags without native admission rather than silently ignoring them. This finding is source-verified; it is not included among the six executed router witnesses.

## Contract completeness

The grant authenticates host/server/tool names but carries no actual agent identity, collector recipient, verifiable parent authority or narrower resource/destination scope. There is no host grant/revocation registry. Native events still use fixed `agent="native-runtime"`, `parent=None`; hooks use `agent="main"`, `parent=None`. No parent authority is intersected with child tools/resources/destinations. These are missing original SOU-63 deliverables 1–3, not evidence of an HMAC forgery. Either implement the selected runtime binding/narrowing or explicitly refuse unsupported protected paths and document the support matrix. Current tests/evidence prove MCP-to-hook propagation, not the mandatory server-A-to-server-B and hook-to-MCP acceptance flows.

## What passed

- All 59 shipped native endpoint tests passed in the isolated source copy.
- All 10 child-authority unit tests passed.
- Contract `sw-child-authority/1`, key derivation domain `agentfw/child-authority-key/v1\0`, separate signature domain, field length prefixes/tool count and nonce coverage are consistent.
- HMAC verification uses `ConstantTimeEq`; malformed claims, wrong key/session/server and expiry at initial verification are covered.
- The added native audit record does not serialize the child grant or derived key. Successful-flow audit tests cover token omission. This is not a claim that all possible diagnostic/forensic capture paths were exhaustively verified.

## Evidence and reproduction

`results.json` pins the source and lists observed outcomes without raw credentials. `reviewer-witnesses.patch` adds six negative tests to an isolated copy of the existing router test fixture. Apply it only in a disposable checkout of the pinned head, then run:

```sh
cargo test --offline -p agentfw --test native_endpoint reviewer_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint -- --skip reviewer_
cargo test --offline -p agentfw --lib native::child_authority
```

The first command currently fails all six intended security assertions; the latter commands pass 59 and 10 tests. Testing here used a source archive under `/private/tmp/sou63-review`, a separate Cargo target, no network, and a macOS sandbox denying writes outside that temporary directory. No real destructive operation or external delivery was performed. Full workspace tests, Clippy and the complete stdio suite were not rerun during this focused review.
