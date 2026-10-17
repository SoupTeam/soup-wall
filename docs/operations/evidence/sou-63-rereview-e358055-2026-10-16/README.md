# SOU-63 re-review of e358055 — REQUEST CHANGES

Reviewed PR #146 exact head `e358055ff937cc9cc4eafb29163f5866970949ea`. All 76 shipped native endpoint and 13 hook endpoint tests passed in an isolated exact-head copy. Both previous nested-field witnesses now pass. Structural separation of nested fields and the fallback marker for active host sessions are credited. Two remaining P1 blockers were independently verified.

## 1. P1 — Opposite mutex acquisition order can deadlock the daemon

At `handlers.rs:345-347`, mark_lossy_provenance takes st.firewall and then calls native.active_host_sessions(), which takes native.sessions. The native inspect path at `native.rs:729-737` takes native.sessions and then st.firewall, holding both through inspection. A malformed/oversized hook without a recoverable root session and a concurrent native event can therefore form a wait cycle, blocking inspection globally.

The independent unit witness deliberately holds native.sessions at the real native-inspect preemption point, starts the actual hook handler with authenticated malformed input, and observes the hook acquire st.firewall while waiting for native.sessions. An actual native inspection continuing from that point would wait for the hook's firewall guard. The witness releases its controlled guard to let the hook finish and reports the inversion, rather than leaving a hung test process. This is a controlled lock-order witness, not a claim that the fixture was left permanently deadlocked.

Snapshot active hosts before acquiring firewall, or otherwise enforce native.sessions → firewall ordering everywhere. Do not call native locking APIs while holding firewall. Add a concurrent malformed-hook/native-event regression.

## 2. P1 — Ambiguous root events still fall through to no-opinion

Two router witnesses demonstrate incomplete use of the new parser:

- **Complete duplicate event, under the cap:** root hook_event_name appears as PostToolUse and PreToolUse in the same payload, with Bash tool/command. The strict HookPayload deserializer rejects the duplicate, and RootJsonScan correctly records it. But at `handlers.rs:575-590`, is_protected_pretooluse returns false because the event is ambiguous, and the handler returns HTTP 200 `{}` in enforce mode. Detecting ambiguity must not turn a potentially protected request into permission to proceed.
- **Duplicate after retained prefix:** an early root PostToolUse is followed by padding and a later duplicate PreToolUse. The capped prefix has closed_object=false and cannot prove that no duplicate follows, but `RootJsonScan::is_proven_non_pre` at `handlers.rs:191-209` nevertheless returns true. The oversized branch exempts the request and returns `{}`. A partial field is not proof of a complete unambiguous event envelope.

Use a single conservative error disposition for malformed, duplicated or incomplete protected identity/event data. Require validated, complete, unambiguous evidence before applying a non-PreToolUse compatibility exemption. Prefix observations cannot prove uniqueness of unseen fields. Keep incomplete-history attribution conservative for ambiguous session identities too; do not create another heuristic spelling-specific exception.

## Evidence and reproduction

`reviewer-witnesses.patch` contains only tests added to the exact-head scratch copy: two integration witnesses and one unit witness inside the existing native test module. Apply only in a disposable checkout:

```sh
cargo test --offline -p agentfw --test native_endpoint reviewe358_ -- --nocapture
cargo test --offline -p agentfw --lib reviewe358_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint --test hook_endpoint -- --skip reviewe358_
```

Current results: both router security assertions fail; the lock-order assertion fails; all 76/13 shipped endpoint tests pass. `results.json` pins source/patch hashes and records observations without credentials or private payloads. Testing used `/private/tmp/sou63-review/e358055`, separate Cargo output and a macOS sandbox denying network and writes outside review scratch. Product sources/tests were not modified. No tool command, external delivery, commit, push or message was performed. Full workspace and Clippy were not independently rerun during this focused pass.

This focused review does not establish completion of the broader original actual-agent/parent authentication, narrower delegated resources/destinations, restart/replay/revocation and support-matrix requirements already identified in earlier reports.
