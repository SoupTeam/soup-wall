# SOU-63 re-review of e3118ee — REQUEST CHANGES

Exact PR #146 head `e3118ee8f0068d98b2a4c710ac5fca8d1aeb914a`. All 81 shipped native endpoint tests, 13 hook endpoint tests and the previous lock-order unit witness passed in an isolated copy. The cec7eaf truncated-tool-name witness is fixed and credited. The reordered ambiguity checks are effective in the malformed-JSON branch.

## P1 — Successful JSON decoding bypasses supported PreToolUse shape validation

Anchor: `crates/agentfw/src/handlers.rs:661-705`, before sequence allocation/mapping and policy inspection. Related permissive wire fields: `crates/agentfw/src/hook.rs` and mapping defaults in `map.rs`.

The new has_protected_tool checks run only when HookPayload deserialization fails. However, HookPayload deliberately accepts missing/null tool_name and missing/arbitrary tool_input. These unsupported PreToolUse shapes therefore take the successful decoding branch, reach mapping/policy without a trustworthy tool/argument identity, and return HTTP 200 `{}` in enforce mode. A no-opinion response permits host continuation rather than explicitly refusing incomplete inspection.

An independent table-driven router witness exercises the whole adjacent family, not just the original truncated string:

| Authenticated PreToolUse case, enforce=true | Observed response |
| --- | --- |
| Missing tool_name, command present | 200 `{}` |
| tool_name=null, command present | 200 `{}` |
| tool_name="", command present | 200 `{}` |
| Bash with missing tool_input | 200 `{}` |
| Bash with tool_input={} | 200 `{}` |
| Bash with numeric command | 200 `{}` |

All six cases share session_id=host. The first three include a destructive command solely as synthetic input; nothing is executed. All six fail the expected explicit Ask/Deny assertion. This does not re-open the repaired truncated-tool witness: it is the successful-deserialization path left outside that repair. SOU-63 deliverable 4 explicitly requires documented enforce dispositions for malformed/missing fields and unsupported protected PreToolUse shapes.

Validate supported PreToolUse semantics before mapping and policy: require a valid nonempty tool identity, and for supported Bash require the expected argument object and command type. Unsupported/missing/ambiguous identity must not be treated as proven read-only. Use a common disposition for both decoding errors and semantically invalid decoded payloads, with an explicit enforce refusal; retain legacy/shadow compatibility deliberately. Do not attempt to solve this solely by adding another condition inside has_protected_tool, because these cases never enter that error branch.

## Reproduction

Apply `reviewer-witnesses.patch` only to a disposable checkout of the pinned head:

```sh
cargo test --offline -p agentfw --test native_endpoint reviewe311_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint --test hook_endpoint -- --skip reviewe311_
cargo test --offline -p agentfw --lib reviewe358_
```

The added test prints all six responses before failing its final assertion. All 81/13 shipped endpoint tests and the prior lock-order witness pass. `results.json` pins source/patch hashes and observed results without credentials or private payloads. Testing used `/private/tmp/sou63-review/e3118ee` with separate Cargo output and a macOS sandbox denying network and writes outside review scratch. Product source/tests were not modified. No command execution, commit, push or external message occurred. Full workspace and Clippy were not independently rerun during this focused review.

This focused pass does not establish completion of the broader original actual-agent/parent authentication, narrowed delegated resource/destination authority, restart/replay/revocation and support-matrix deliverables previously identified.
