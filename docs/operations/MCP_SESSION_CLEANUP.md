# Cleanup of lost MCP sessions, authenticated liveness, and capacity recovery

The Agent daemon enforces bounded session capacity (`MAX_SESSIONS = 64`) and
per-agent identity bindings for authenticated MCP collectors. When client,
collector, or server processes terminate unexpectedly (e.g. abrupt crash,
`SIGKILL`, network partition, or unhandled exit), unleased sessions previously
lingered in daemon state until the inactivity TTL (300s) elapsed, consuming session slots,
blocking restarted agents with `native_agent_already_bound`, and retaining
provenance tracking context allocations until unrelated incoming traffic triggered cleanup.

SOU-89 introduces authenticated native session liveness (`sw-native-liveness/1`),
proactive bounded daemon maintenance reclamation, and a unified terminal retirement path
that restores capacity within a predeclared finite cleanup deadline while strictly preserving
shared-host risk, taint floors, and audit integrity.

---

## Authenticated native liveness contract (`sw-native-liveness/1`)

The liveness contract is versioned separately from the core admission contract (`sw-native/1`)
and is exposed at `/native/liveness/v1`. Enrolled collectors actively declare their leases
and maintain continuous liveness.

### Protocol parameters and limits

- **Contract Version**: `sw-native-liveness/1`
- **Default Lease**: `10` seconds (configurable via `config.native.liveness.default_lease_seconds`)
- **Minimum Lease**: `1` second (`MIN_LEASE_SECONDS = 1`)
- **Maximum Lease**: `60` seconds (`MAX_LEASE_SECONDS = 60`)
- **Renewal Period**: `lease_seconds / 3` (collectors renew well before half-life)
- **Retry Budget**: at most `3` attempts with at most `50ms` backoff; lease uncertainty stops further execution
- **Maintenance Sweep Interval**: `500` ms (clamped between 50ms and 10,000ms; configurable via `config.native.liveness.maintenance_interval_ms`)
- **Finite Cleanup Deadline**: `lease_duration + (2 * maintenance_interval)` (typically under 12 seconds for default lease; under 2 seconds for 1-second lease)

### Contract actions

Bootstrap is also opt-in: send `"liveness": "sw-native-liveness/1"` on an authenticated `session_start` to receive the `instance_id` and private `owner_token` needed for enrollment. A legacy start without this field keeps the accepted receipt schema and remains unleased. Selecting an existing server profile alone does not enable liveness: configure the liveness lease or set `AGENTFW_NATIVE_LIVENESS=true` explicitly. Unknown bootstrap versions fail closed.

Epochs also appear in audit records and are not ownership credentials. Enrollment, renewal and retirement require the per-session `owner_token`, which is never written to audit. The daemon bearer token remains required. A token from a sibling session is refused.

1. **`enroll`**:
   - Request: `{"contract_version": "sw-native-liveness/1", "registry_sha256": "...", "session_id": "...", "instance_id": "...", "action": "enroll", "lease_seconds": 15, "owner_token": "..."}`
   - **Per-session owner authentication**: `owner_token` returned during `session_start` must be presented and is verified in constant time (`subtle::ConstantTimeEq`). Merely possessing the shared daemon token and knowing or guessing a `session_id` is rejected with `403 Forbidden` (`native_liveness_owner_token_required` or `native_liveness_owner_mismatch`).
   - **Re-enrollment rejection**: Attempting to re-enroll an already enrolled session (whether active, expired, or terminal) is rejected with `409 Conflict` (`native_liveness_already_enrolled` or `native_liveness_terminal`). Expired or retired authority is terminal and cannot be revived; a fresh session must be created.
   - Binds liveness to the exact daemon `instance_id` and the session `epoch` created by `session_start`; enrollment reuses that session's owner capability.
   - Response: `{"contract_version": "sw-native-liveness/1", "action": "enroll", "instance_id": "...", "session_id": "...", "epoch": "...", "lease_seconds": 15, "lease_seq": 1, "expires_in_ms": 15000, "status": "active"}`

2. **`renew`**:
   - Request: `{"contract_version": "sw-native-liveness/1", "registry_sha256": "...", "session_id": "...", "instance_id": "...", "action": "renew", "owner_token": "...", "epoch": "...", "lease_seq": 2}`
   - Monotonicity: `lease_seq` must be strictly greater than the last accepted `lease_seq`. Stale sequences or replays return `409 Conflict` (`native_liveness_seq_stale`).
   - Authority Ceiling: A lease renewal cannot extend signed child authority (`authority_expires_at_ms`) or parent validity. If signed authority has expired, renewal returns `409 Conflict` (`native_liveness_authority_expired`).
   - Terminal Immunity: Once a session is terminal (retired, expired, or ended), renewal returns `404 Not Found` or `409 Conflict` (`native_liveness_terminal`). Authority cannot be revived.

3. **`retire`**:
   - Request: `{"contract_version": "sw-native-liveness/1", "registry_sha256": "...", "session_id": "...", "instance_id": "...", "action": "retire", "owner_token": "...", "epoch": "..."}`
   - Triggers definitive closure of the session and all its descendants via the unified terminal retirement path.

4. **`status`**:
   - Read-only check returning remaining lease milliseconds and state (`"active"`, `"expired"`, `"retired"`).

---

## Unified terminal retirement path (`retire_sessions_terminal`)

All paths that lead to definitive session closure—explicit `session_end`, `liveness.retire`,
autonomous background maintenance reclamation, parent session termination, and agent re-binding—converge
on a single unified terminal retirement path. An enrolled session's explicit `session_end` spends its signed grant and retires its entire descendant tree immediately, including unleased descendants. Legacy unleased `session_end` behavior remains compatible:

1. **Terminal state latch**: Marks `session.terminal = true` and `lease.state = LeaseState::Terminal(reason)`. No subsequent renew, call, or retry can resurrect this session.
2. **Cascade child retirement**: Automatically traces the provenance tree (`parent_epoch`) and terminally retires all descendant child sessions.
3. **Pending approval closure**: Closes all outstanding operator approvals for the session via `approval.close_session(id, reason)`.
4. **Firewall agent termination**: Unregisters agent tools via `firewall.end_agent(host, agent)` and inspects `EventKind::SessionEnd`.
5. **Span eviction**: Evicts session spans from `st.spans`.
6. **Audit-before-release**: Formats and persists an audit record (`native_session_{reason}`) via `st.audit.write_native`. If writing the audit record fails, `firewall.mark_all_provenance_incomplete()` is immediately asserted to ensure safety floors fail closed.
7. **Continuity checkpointing**: Invokes `continuity.commit(st, native)` to persist profile transition gates and session state. If checkpointing fails, provenance is marked incomplete; authority is never revived.

---

## Autonomous daemon maintenance worker

A dedicated background maintenance task is spawned during `agentfw serve` startup:
- Periodically executes `agentfw::native::liveness::perform_maintenance`.
- Inspects session liveness leases using monotonic `Instant::now()`, legacy inactivity TTL (300s), and signed child authority deadlines (`now_ms >= exp`).
- Sweeps dead and expired sessions without requiring any incoming HTTP traffic.
- Serializes with the profile continuity transaction gate, including the first activation before continuity is enabled.
- Samples monotonic and authority clocks after acquiring state locks; time spent waiting cannot renew an expired lease. Session-start cleanup also refreshes clocks and managed-policy state after reacquiring locks.
- Restores daemon session and call capacity deterministically within the predeclared deadline.

---

## Read-only instance endpoint (`GET /native/v1/instance`)

Calls to `GET /native/v1/instance` are strictly read-only:
- The response filters out dead, expired, or terminal sessions from the returned `bindings` array.
- It no longer performs ad-hoc mutations or deletions bypassing continuity middleware or audit logging.

---

## Security invariants preserved

1. **Host-level taint and incomplete floors**: Shared host provenance history and taint floors are tied to `host_session`, not collector session epochs. Reclaiming an orphaned collector never clears or weakens host taint.
2. **Sticky incomplete-history floors**: Any failure during audit emission or continuity commitment marks all provenance contexts incomplete, preserving fail-closed policy enforcement.
3. **Scoped host tombstones**: `state.scoped_hosts` remains bounded at 64 and is never evicted during session cleanup (`scoped_host_capacity_never_evicts_completed_identity_tombstones`).
4. **Explicit error codes**: Calls directed at an authority-expired session return `native_child_authority_expired`, and calls to sessions whose parent has ended return `native_child_parent_unavailable`. They do not mask the failure as `native_session_unknown` until the session is legitimately reclaimed.
5. **Active grant immutability**: Active unexpired grants cannot be hijacked or overwritten by duplicate agent bootstrap requests.
6. **Replay and forgery protection**: Renewals require knowledge of the exact daemon `instance_id`, session `epoch` and per-session secret `owner_token`, and monotonic sequence numbers. Guessed session IDs or child messages cannot renew or retire peer sessions.

---

## English operator recovery guide

### Symptom: `native_session_cap`
- **Cause**: All 64 session slots are occupied by active, valid sessions.
- **Diagnostics**:
  ```bash
  curl -s -H "Authorization: Bearer $NATIVE_TOKEN" http://127.0.0.1:8080/native/v1/instance | jq .
  ```
  Check `bindings` and `provenance.usage.sessions`.
- **Resolution**:
  - If collectors are enrolled in liveness, orphaned sessions will be automatically reclaimed within their lease deadline.
  - If unleased legacy collectors crashed, wait for the 300-second inactivity TTL, or send `session_end` for completed sessions.

### Symptom: `native_agent_already_bound`
- **Cause**: An orchestrator is attempting to bootstrap an agent under `(host_session, agent_id)` while a previous session for that agent is still live and unexpired.
- **Resolution**:
  - If the previous collector process is still running, shut it down gracefully.
  - If the previous collector terminated abruptly, the daemon will automatically reap the session as soon as its liveness lease or signed authority expires, after which re-binding will succeed automatically.

### Symptom: `native_liveness_uncertain` in collector logs
- **Cause**: The collector detected that its lease renewal failed (e.g. daemon restarted, lease expired, or network partitioned).
- **Resolution**:
  - The collector refuses further native admission and enters accepted owned cleanup.
  - Every host write, flush and shutdown poll rechecks lease uncertainty, including a blocked write becoming writable before the monitor timer fires. Bytes committed before uncertainty was observed cannot be retracted.
  - Restart the collector process with fresh credentials to acquire a new authenticated session.
