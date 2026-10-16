# SOU-48 evidence: native MCP Ask approval and resume

Control-flow demonstration only. A disposable fixture MCP server and a local HTTP
receiver stand in for a real tool; no model, dataset, label, or classifier selection
is involved, and nothing here supports a generalization claim. The feature is opt-in
and off by default; it is not enabled in production.

## Reproduce (Linux/macOS)

```
cargo build -p agentfw
python3 scripts/native-approval-acceptance.py --binary target/debug/agentfw --out eval/evidence/sou48
cargo test -p agentfw --lib approval
cargo test -p agentfw --test mcp_admission sou48
```

The script starts the real `agentfw serve` daemon, the real `agentfw mcp
--native-admission` collector and the real `agentfw native-approval` operator CLI in a
temporary HOME. Independent witnesses: the fixture server's executed-frame ledger
(child calls, exact bytes) and a separate HTTP receiver that the fixture server calls
only when it executes `delete_note` (released effect).

## Controls (`native-approval-acceptance.json`)

| Control | Result |
|---|---|
| zero child calls and zero receiver hits before approval | 0 / 0 |
| approval with a wrong binding digest | refused, still 0 / 0 |
| one correct approval | exactly 1 child call (original frame bytes) and 1 receiver hit |
| replaying the spent approval | refused, no new effect |
| next ordinary call after the approved call | works |
| audit | approval id and digests present; raw arguments absent |
| reject, then late approve | nothing runs; approve refused |
| wait timeout | correlated refusal `native_approval_timeout`, nothing runs |
| hard Deny tool with an operator available | refused, no pending request created |
| extra client input while pending | request cancelled, session closed, late approve refused |
| daemon restart while pending | late approve refused, nothing runs |
| default config (no `native.approval`, no wait flag) | current refusal, no pending request |

## Daemon-boundary controls (unit tests, `native::approval::tests`)

replay and concurrent redemption (8 threads, exactly one release), changed arguments,
other session, policy switch (`invalidate_all_for_policy_switch`), hard Deny with an
approval id, unsupported resource tool, expiry, session end, restart wipe, second
pending request, hook-key-signed grant and old hook approval cannot authorize a native
call, classifier-source approval.

## Identities

`native-approval-acceptance.json` records the base git head, the binary sha256, the
registry sha256, the default config sha256 and the sha256 (CRLF-normalized) of the
changed source files at run time.
