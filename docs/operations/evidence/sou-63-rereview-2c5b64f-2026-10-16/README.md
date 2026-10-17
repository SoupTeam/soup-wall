# SOU-63 re-review of 2c5b64f — REQUEST CHANGES

Exact head: `2c5b64fc3f217db3b2fede6aaeb6e2a56bd293e3`, PR #146. All 78 shipped native endpoint tests and 13 hook endpoint tests passed. The previously supplied lock-order unit witness also passed. Snapshotting native hosts before taking firewall fixes the reported inversion. The previous complete duplicate-event and unclosed event-prefix refusal witnesses pass. Those repairs are credited.

Two additional independent router witnesses reproduce remaining P1 gaps in the claimed malformed-input and incomplete-history protections.

## 1. P1 — Escaped JSON command keys bypass malformed protected-hook refusal

`handlers.rs:279-281` still detects a protected Bash command through raw.contains("\"command\""). The new error branch at `623-641` therefore depends on raw JSON spelling rather than decoded command identity.

The witness sends PreToolUse with tool_name=Bash and deliberately omits the required session_id. The ASCII command key gets the intended deny. Replacing only the key with `"\u0063ommand"` preserves exactly the same decoded tool_input.command, but has_protected_tool returns false and the endpoint returns HTTP 200 `{}` in enforce mode. Both bodies are confirmed as containing the same command by serde_json::Value; both fail HookPayload deserialization because of the missing session.

Do not prove an invalid Bash request unprotected from raw command-key substring absence. Treat declared Bash conservatively in malformed-input handling, or recognize decoded argument keys structurally. Apply the same reasoning to missing/truncated/ambiguous tool identity: inability to prove protection is not proof that an enforce request is safe. Normal valid read-only calls can retain compatibility.

## 2. P1 — Partial root session is still accepted as complete identity proof

At `handlers.rs:376-378`, mark_lossy_provenance accepts get_root_string(session_id) without requiring a validated, complete, unambiguous envelope. This suppresses the conservative active-host fallback. The new closed_object requirement protects event classification, but not session attribution.

The witness establishes a correctly signed child bound to host. It then submits an oversized PostToolUse whose prefix contains session_id=unrelated and whose unseen tail contains a duplicate session_id=host. The complete body is deliberately ambiguous and rejected by the strict HookPayload deserializer; the retained prefix cannot establish root-key uniqueness. Nevertheless, unrelated gets the incomplete marker and the possibly affected active host remains complete. A subsequent host-bound delete_document receives verdict=allow, release=true and a call receipt instead of the required incomplete-history Ask floor. No destructive operation is executed by the witness.

Only authenticated independent context or a fully validated unambiguous identity may narrow loss attribution. For an incomplete/ambiguous root, preserve the fallback over potentially affected active host bindings even if one early session string was observed. Snapshot hosts before taking firewall, retaining the corrected lock order. Merely adding closed_object to the event predicate does not fix this attribution path.

## Reproduction and evidence

Apply `reviewer-witnesses.patch` only in a disposable checkout of the exact head:

```sh
cargo test --offline -p agentfw --test native_endpoint review2c_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint --test hook_endpoint -- --skip review2c_
cargo test --offline -p agentfw --lib reviewe358_
```

Current results: two new assertions fail; all 78/13 shipped endpoint tests and the previous lock-order unit control pass. `results.json` contains source/patch hashes and sanitized observations. Execution used an exact source archive in `/private/tmp/sou63-review/2c5b64f`, separate Cargo output and a macOS sandbox denying network and writes outside review scratch. Product source/tests were not changed; no actual tool execution, commit, push or message was performed. Full workspace, complete stdio suite and Clippy were not independently rerun in this focused pass.

This review does not certify the original broader actual-agent/parent authentication, delegated resource/destination narrowing, replay/revocation/restart and support-matrix deliverables previously identified.
