# SOU-63 re-review of 13743ce — REQUEST CHANGES

Exact head: `13743ced75486a6805d9a79d25dcc0e0fab12e8a`, PR #146. All 70 shipped native endpoint tests passed in the isolated source archive, including the original six witnesses and the five d84072a re-review witnesses. The resolved host-verdict merge, empty scope, expiry, basic active-child lifecycle protection, unauthorized-body early rejection, bounded normal reads and mapped truncation marker are credited. They are not being re-reported as the same failing witnesses.

Four additional deterministic router witnesses expose three remaining error-path blockers:

1. **[P1] Oversized protected-hook refusal depends on JSON field order — `handlers.rs:305-318`.** With enforce=true and max_body_bytes=1024, send valid JSON ordered as session_id, 6000 bytes of padding, then hook_event_name=PreToolUse, tool_name=Bash and its command. The reader retains only a prefix; `is_protected_pretooluse(prefix)` cannot see the event/tool and returns false. The endpoint returns HTTP 200 `{}` instead of the documented protected enforce refusal. JSON members are unordered, and dropping body suffixes must not downgrade an otherwise supported protected request. In enforced authenticated mode, ambiguous truncated identity/event data needs a conservative refusal or trusted independently bound event metadata; treating it as a legacy unknown event allows bypass. The witness does not execute the command.

2. **[P1] Body errors are treated as clean input — `handlers.rs:148-165`.** A body stream containing a valid PostToolUse JSON prefix followed by an UnexpectedEof error reaches `Err(_) => break`, then returns Ok(prefix). The request is inspected as complete and `provenance_incomplete(host)` stays false, despite an active authenticated child binding. A second witness puts an invalid UTF-8 byte in a protected PreToolUse command. `from_utf8_lossy` repairs it into accepted JSON and the hook returns `{}` instead of the malformed-input refusal. Return explicit typed failures for transport errors and invalid UTF-8; never manufacture a successful EOF or silently reinterpret invalid wire bytes. Apply failure disposition and incomplete-history handling to the authenticated session when known. The helper is shared by `/hook` and `/mcp`.

3. **[P1] Empty session bypasses the malformed protected-request refusal — `handlers.rs:352-378`.** A complete authenticated PreToolUse/Bash payload with `session_id=""` passes deserialization. `map::to_event` refuses its identity, but that branch records an unknown/allow audit and returns `{}`. It never uses the new protected enforce refusal applied to serde errors. Reject invalid identities for protected enforce requests explicitly, without allocating shared state under an empty ID; retain compatibility only for genuinely unsupported/unprotected cases. The original SOU-63 deliverable explicitly includes malformed/missing session fields.

## Reproduction and evidence

Apply `reviewer-witnesses.patch` only to a disposable checkout of the pinned head:

```sh
cargo test --offline -p agentfw --test native_endpoint review137_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint -- --skip review137_
```

The first command currently fails all four intended security assertions; all 70 shipped tests pass. `results.json` pins source and patch hashes and records observed outcomes without credentials/private payloads. Execution used `/private/tmp/sou63-review/13743ce` with a separate Cargo target and macOS sandbox denying network and all writes outside review scratch. Product sources were not changed; no real tool execution, network delivery, commit, push or external message was performed. Full workspace tests and Clippy were not independently rerun in this focused review.

This report concerns the changed code and its error paths. It does not establish completion of the broader original actual-agent/parent identity, delegated resource/destination narrowing, replay/revocation/restart and support-matrix requirements identified in the first review.
