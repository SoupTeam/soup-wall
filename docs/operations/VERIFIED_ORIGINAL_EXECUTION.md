# Daemon-owned original execution binding (SOU-155)

Status: interface/security proposal on accepted main
`3c9cfb08c0f1498676dcc70de131bd2f324dd13b`. This document is not implementation,
independent qualification or permission to enable structural-text relief.
The remaining SOU-142 owner-self-loss handoff precedes substantial execution work.

## Threat model and compatibility

The daemon and explicitly operator-selected catalogue are the trust root. Project
data, original server output, ordinary collectors and wire metadata are untrusted.
Native owner/child capabilities establish authority, not formatter provenance.
Neither `native/1`, an install digest, schema, PID, formatter-looking text nor a
client-supplied flag can construct the new evidence.

Start with the accepted original Linux filesystem read-only profile. Other
platforms, arbitrary runtimes, Git-specific object semantics and the create-only
profile retain their existing paths and baseline inspection until independently
implemented/qualified. Tool names, exact arguments/result bytes, policy floors,
Ask redemption, OS confinement, limits and result inspection remain mandatory.
This component never asserts that an authenticated result is benign.

## Proposed additive contract

`sw-mcp/verified-original-execution/1` denotes daemon-established execution
custody. It is separate from native policy authority. A selected catalogue entry
is loaded from bounded operator-owned configuration, never a profile path or
runtime supplied by an MCP request. Unsupported/missing qualification preserves
baseline inspection or the existing required refusal; no implicit upgrade.

The public contract carries an opaque evidence reference and finite descriptive
identities. Its authority exists only as a non-deserializable daemon-owned record.
No `trusted=true` or signed server/collector statement is accepted as proof.
The record binds:

| Field | Source of evidence |
| --- | --- |
| Daemon instance and native session/epoch | Current daemon state; invalid after restart/revocation |
| Operator catalogue generation and closure SHA-256 | Verified immutable runtime selection |
| Runtime, formatter/dependency, profile/schema and sandbox/environment identities | Bytes and fixed execution inputs actually consumed by launch |
| Process generation and private channel instance | Daemon-created process, pidfd/start identity and exclusive stdio custody |
| Native call ID, exact host JSON-RPC ID, tool/argument/raw-request digests | Current admitted invocation and bytes actually dispatched |
| Original response/frame digest and length | Bytes read by the daemon from its own child's output channel |
| Deadline, lifecycle and consumed state | Existing native call lifetime and daemon-owned one-use ledger |
| Optional domain witness kind and digest | Separately reviewed producer; initially absent |

The proposed optional witness extension is domain-tagged, not generic trust.
SOU-156 owns resolved Git object/snapshot semantics; its producer must establish
those facts independently. A future consumer may combine that witness with the
execution record only when source, session, exact call and original result match.
The current component does not issue a Git witness or duplicate SOU-109 parsing.

## Launch and channel custody

The daemon selects and verifies the runtime closure, creates the private original
process channels and retains exclusive custody of original stdin/stdout. Collectors
do not supply a result FD or choose a replacement executable. Reuse the existing
Linux namespace owner, authenticated private startup capsule, adoption boundary,
pidfd generation checks, cgroup enforcement and verified cleanup primitives.

A profile/install directory alone is mutable. Launch qualification requires exact
immutable executable, formatter/dependency and loader/library bytes through the
verification-to-execution interval. A directory FD or before/after mtime is not
that protection. Sealed descriptor-backed images and bounded namespace data
mounts are candidate existing primitives; the actual original filesystem closure
must fit reviewed descriptor/argv/byte bounds. Missing support refuses attestation
without changing the legacy runtime. Final transport/cap bounds must be fixed from
the real selected closure and reviewed before implementation; no broad bound is
raised merely to make a failing acceptance pass.

The daemon validates an active native call before dispatching a `tools/call` and
again before retaining/consuming result evidence. An ordinary collector cannot
use launch IPC to bypass a Deny, pending Ask, spent call or session revocation.
Initialization/discovery use the accepted bounded selected-server contract and
never dispatch a tool as a side effect. Original framing/progress/result bounds
remain enforced; malformed or unmatched frames cannot mint evidence.

## Lifecycle and concurrency

1. Reserve current session/call ownership before external execution. A request
   cannot transfer evidence to another session, host ID, call, argument or result.
2. Register the actual process generation and daemon-owned channels before its
   original tool execution. No state is inferred from a bare numeric PID.
3. Correlate the exact written invocation and original response inside daemon
   custody. Concurrent responses are keyed by exact JSON-RPC identity; duplicate,
   substituted, unsolicited or ambiguous responses never authenticate.
4. Evidence expires no later than the existing native call. Consumption is atomic
   and single-use, including invalid reuse attempts. No authority/TTL extension.
5. Cancellation, parent/process replacement, server/daemon restart, liveness loss
   and uncertain cleanup revoke evidence. No mutex is held across process I/O;
   native session ownership precedes the evidence-ledger lock during final checks.
6. Result inspection always uses existing baseline floors in this PR. A later
   independently reviewed SOU-109 integration may consume the private typed record;
   serializing its metadata back through a client cannot recreate it.

## Required independent native controls

Actual pinned original filesystem positive; identical-format alternate runtime
negative; executable/formatter replacement before and during launch; forged and
replayed references; cross-call/session/result substitution; concurrent calls;
generation/PID reuse; restart, cancellation, expiry and incomplete cleanup.
Retain useful original reads, Ask behavior and Deny zero-effects. Observe actual
source, closure/process/channel identities and bytes, not only mocked decisions.
macOS parser tests do not qualify Linux custody. Keep every failed/incomplete run.

Migration remains opt-in and additive. Draft development uses focused checks; one
final Ready/current-main qualification, admission and merge are TL-owned. No
production relief, new inference/policy behavior, paid calls or unsupported-platform
claims are enabled by this proposal.
