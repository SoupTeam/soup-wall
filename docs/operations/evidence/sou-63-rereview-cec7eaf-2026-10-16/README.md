# SOU-63 re-review of cec7eaf — REQUEST CHANGES

Exact PR #146 head: `cec7eafbfd14d8eb5a464b05bbf2778795887d66`. All 80 native endpoint tests and 13 hook endpoint tests passed; the previous lock-order unit witness also passed. Both previous 2c5b64f findings are fixed: escaped command keys no longer disable malformed Bash refusal, and unclosed/ambiguous session prefixes retain the active-host incomplete-history fallback. Those repairs are credited.

## P1 — Incomplete tool identity is still treated as permission to proceed

At `crates/agentfw/src/handlers.rs:277-285`, has_protected_tool returns false when no complete tool string was recovered, before checking incomplete_keys. The malformed-hook handler at `648-669` requires has_protected_tool=true before producing an enforce refusal, so an identified PreToolUse whose tool name is incomplete is silently released as no-opinion.

The independent router witness sends authenticated, enforce-mode input ending at:

```text
{"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Ba
```

RootJsonScan correctly identifies the root event as PreToolUse and records tool_name as incomplete. The body is not above the cap; strict JSON decoding fails. The error branch nevertheless returns HTTP 200 `{}`, with no permissionDecision, instead of the required conservative refusal for an unsupported/incompletely inspected protected invocation. No command is executed.

Unknown/incomplete/ambiguous tool identity must not be interpreted as a proven unprotected tool. Check ambiguity before empty-recovery shortcuts and make the error disposition conservative for known PreToolUse unless a supported benign case is positively established. Apply the same rule to missing/non-string tool identity and partial key/value shapes, rather than fixing only one spelling. The task's original hook-hardening requirement includes malformed/missing fields and unsupported protected PreToolUse shapes.

## Reproduction

Apply `reviewer-witnesses.patch` only in a disposable checkout of the pinned head:

```sh
cargo test --offline -p agentfw --test native_endpoint reviewcec_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint --test hook_endpoint -- --skip reviewcec_
cargo test --offline -p agentfw --lib reviewe358_
```

Current result: the additional security assertion fails; all 80/13 shipped endpoint tests and the prior lock-order control pass. `results.json` records source/patch hashes and sanitized outcomes. The review used an exact source archive under `/private/tmp/sou63-review/cec7eaf`, separate Cargo output and a macOS sandbox denying network and writes outside review scratch. Product source/tests were not modified; no real tool execution, commit, push or external message occurred. Full workspace and Clippy were not independently rerun.

This focused pass does not certify completion of the original actual-agent/parent authentication, narrower delegated resource/destination scope, restart/replay/revocation and support-matrix deliverables previously identified.
