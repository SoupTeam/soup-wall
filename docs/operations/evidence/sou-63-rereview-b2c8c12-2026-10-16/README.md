# SOU-63 re-review of b2c8c12 — REQUEST CHANGES

Reviewed exact head `b2c8c121885efd40af83330fbd3ebcd74c0e0d68`, PR #146. All 74 shipped native endpoint tests passed, including all previous integrated witnesses. The three prior fixes are credited: typed body read failures, explicit empty-session refusal and conservative oversized-body handling when event recovery is unambiguous. Product sources/tests were not changed.

## Remaining P1: substring recovery is not proof of top-level event/session identity

Anchors: `crates/agentfw/src/handlers.rs:38-47`, `64-71`, and their security-sensitive use at `332-355`.

When a retained body prefix is not complete JSON, `extract_event_from_raw` and `extract_session_id_from_raw` fall back to `find()` over raw text. They do not track JSON nesting or establish that a matched name belongs to the root object. The error handler nevertheless treats recovered event names as proven exemptions from refusal and recovered session names as authority for the incomplete-history marker.

Two independent executed witnesses demonstrate the consequences with valid complete JSON and max_body_bytes=1024:

1. Put `metadata.hook_event_name="PostToolUse"` before 6000 bytes of padding, with the actual root `hook_event_name="PreToolUse"`, `tool_name="Bash"` and command after padding. The actual protected event is unambiguously PreToolUse in the original request, but the retained prefix contains only the nested PostToolUse name. The handler treats it as `is_proven_non_pre=true` and returns HTTP 200 `{}` instead of deny in enforce mode. No command was executed by the witness.
2. Keep root `hook_event_name="PostToolUse"` early, put `metadata.session_id="unrelated"` before padding, and the actual root `session_id="host"` after padding. Establish a correctly signed active child bound to host first. The discarded untrusted result marks unrelated incomplete, while `provenance_incomplete("host")` stays false. The actual host can therefore lose the required floor while an unrelated session receives it.

Use bounded structural parsing that distinguishes root fields, nesting, strings/escapes and duplicate/ambiguous fields. A raw substring match is not proof that the request is non-PreToolUse. If the actual host identity is unavailable within the cap, it must not be replaced with a nested correlation string: use the trusted host binding/context or conservatively preserve incomplete-history protection for potentially affected active bindings. In enforce mode, absence of proof must not authorize a protected request. Keep legacy exemptions explicitly tied to validated supported events. Add field-order/nesting/duplicate/escape and incomplete-prefix controls so repairs cover the parser boundary rather than this one spelling.

## Reproduction

Apply `reviewer-witnesses.patch` only in a disposable checkout of the pinned head:

```sh
cargo test --offline -p agentfw --test native_endpoint reviewb2_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint -- --skip reviewb2_
```

Current result: both independent security assertions fail; all 74 shipped tests pass. `results.json` pins source and patch hashes and records observations without credentials or private payloads. Execution used an exact source archive under `/private/tmp/sou63-review/b2c8c12`, separate Cargo output, no network and a macOS sandbox denying writes outside review scratch. No product change, destructive command, external delivery, commit, push or message was performed. Full workspace, Clippy and the stdio suite were not independently rerun in this focused pass.

As in earlier reports, passing this focused router review would not by itself establish completion of the original actual-agent/parent authentication, narrower delegated resources/destinations, restart/replay/revocation and support-matrix deliverables.
