# Cleanup of lost MCP sessions and capacity recovery

The Agent daemon enforces bounded session capacity (`MAX_SESSIONS = 64`) and
per-agent identity bindings for authenticated MCP collectors. When client,
collector, or server processes terminate unexpectedly (e.g. abrupt crash,
`SIGKILL`, network partition, or unhandled exit), sessions could previously
linger in daemon state until idle TTL (300s) elapsed, consuming session slots,
blocking restarted agents with `native_agent_already_bound`, and retaining
provenance tracking context allocations.

SOU-89 introduces automatic cleanup of lost and orphaned MCP sessions and
restores capacity without weakening security guarantees.

## Lost session detection and reaping

A session is considered lost / dead if any of the following conditions hold:
1. **Idle timeout**: `now.duration_since(session.touched) >= TTL` (300s).
2. **Expired child authority**: `authority_expires_at_ms` is set and monotonic
   wall-clock time has passed the expiration deadline (`now_ms >= exp`).
3. **Broken lineage**: `validate_lineage` fails because any ancestor in the
   delegation chain has expired authority or the registered parent session has
   ended or been replaced.

When reaped:
- The session is removed from `state.entries`.
- Pending approval requests for the session are closed with `session_expired`.
- Agent tool registrations in `firewall` are retired via `end_agent`.
- Session provenance contexts (`session.epoch`) are retired in `firewall` via
  `EventKind::SessionEnd`.
- Span cache records for the session epoch are dropped.

## Capacity recovery in `session_start`

When a new session is requested via `session_start`:
- If `state.entries.len() >= MAX_SESSIONS`, the daemon automatically sweeps
  and reaps dead and expired sessions before evaluating the capacity limit.
- If dead sessions were occupying capacity, their slots are freed immediately,
  allowing the new session to proceed. If all 64 slots are occupied by active,
  valid sessions, `native_session_cap` is returned.
- Reusing an existing `session_id` is permitted if the prior session with that ID
  has died or expired, avoiding false `native_session_exists` errors while
  strictly protecting active sessions.

## Agent re-binding

When an agent crashes or its child authority expires, the orchestrator or
supervisor may restart the agent under the same `(host_session, agent_id)` pair:
- Before checking `native_agent_already_bound`, the daemon inspects any existing
  session bound to that `(host_session, agent_id)`.
- If the existing session is dead (authority expired, lineage broken, or timed out),
  it is reaped immediately, allowing the restarted agent to bind cleanly with
  its fresh authority grant.
- If the existing session is still active and valid, the duplicate bootstrap is
  rejected with `native_agent_already_bound` (`duplicate_agent_bootstrap_never_overwrites_an_active_grant`).

## Instance endpoint observability

Calls to `GET /native/v1/instance` trigger lost session cleanup:
- Stale bindings for dead or expired sessions are pruned.
- Returned `bindings` and `provenance.usage` (`sessions`, `retained_bytes`)
  accurately reflect live, active sessions.

## Collector signal resilience

In addition to daemon-side cleanup, MCP collectors (`agentfw mcp --native-admission`)
intercept `SIGINT` (e.g. `Ctrl-C`) in their relay transport loops:
- Upon receiving `SIGINT`, the relay loop breaks cleanly.
- Process and diagnostic cleanup runs.
- The collector attempts to send `session_end` to the daemon before exiting,
  ensuring prompt resource deallocation.
- If the collector is killed with `SIGKILL` or crashes before sending `session_end`,
  the daemon-side lost session cleanup handles reclamation automatically.

## Security invariants preserved

1. **Host-level taint and incomplete floors**: Shared host provenance history
   and taint floors are tied to `host_session`, not child session epochs.
   Reaping an orphaned child session never clears or weakens host taint.
2. **Scoped host tombstones**: `state.scoped_hosts` remains bounded at 64
   and is never evicted during session cleanup (`scoped_host_capacity_never_evicts_completed_identity_tombstones`).
3. **Explicit error codes**: Direct tool calls directed at an authority-expired
   session return `native_child_authority_expired`, and calls to sessions whose
   parent has ended return `native_child_parent_unavailable`. They do not mask
   the failure as `native_session_unknown` until the session is legitimately
   reclaimed.
4. **Active grant immutability**: Active unexpired grants cannot be hijacked or
   overwritten by duplicate agent bootstrap requests.
