# Daemon-owned original execution binding (SOU-155)

Development implementation on accepted base
`379f9f9a17ec7369acaa65455d26f745c36ab866`. Native qualification is still pending;
this document does not claim merge readiness. The remaining SOU-142 outside-owner
SIGKILL delivery was transferred to @waattoo on October 26 and is not a SOU-155
dependency. Its separate diagnostic handoff remains in PR #272.

## Trust and scope

The running daemon, operator-selected catalogue and host kernel/process custody
are the trust root. MCP requests, project data, ordinary collector statements,
server output and copied metadata are untrusted. A native capability, installation
hash, schema, PID or formatter-looking text alone cannot create execution evidence.
This protocol does not protect a compromised daemon or an attacker with control
over the host OS identity/process boundary. It makes no stronger sandbox claim.

The initial producer supports the accepted original Linux x86-64 filesystem
read-only runtime. Git object semantics belong to SOU-156. Create-only, arbitrary
runtimes, other platforms and existing native/1 clients retain their original
paths and baseline inspection. This PR enables no structural-text relief, new
model inference, policy changes or bypass of result inspection. Authenticated
original output can still contain hostile content and remains untrusted.

## Operator selection and immutable closure

`native.execution` is opt-in daemon configuration:

```yaml
native:
  registry_path: /operator/agent/registry.json
  registry_sha256: <sha256>
  liveness:
    default_lease_seconds: 10
    max_lease_seconds: 30
    maintenance_interval_ms: 100
  execution:
    catalogue_path: /operator/agent/original-filesystem.json
    catalogue_sha256: <sha256-of-exact-catalogue-bytes>
```

The bounded catalogue is an owned, non-shared-writable regular file. Linked paths,
unknown/duplicate fields, mismatched hashes and unsupported profiles are refused.
Its JSON shape is:

```json
{
  "format": "sw-mcp/original-execution-catalogue/1",
  "server_id": "filesystem",
  "profile": { "...": "complete existing filesystem ProfileConfig, including workspaceIdentity" },
  "classifier": {
    "script": "/operator/rule_baseline.py",
    "script_sha256": "<sha256>",
    "python": "/operator/python3",
    "python_sha256": "<sha256>"
  },
  "approval_wait_seconds": 0,
  "budget": {
    "binding": "/operator/run/binding.json",
    "budget_sha256": "<existing prepared-budget identity>"
  }
}
```

`budget` is optional. Its presence requires the existing exact host-bound prepared
selection, delegated-root identity and private records; failure cannot retry
unbudgeted. The daemon supplies execution inputs explicitly, without mutating its
process environment or accepting caller-provided paths/commands/classifiers.
Approval wait requires the existing configured single-use approval service.

At daemon startup, the complete installed package tree, official Node image,
bubblewrap and declared loaders/libraries are copied into sealed descriptor-backed
images. Digests are calculated from the copied bytes actually consumed by launch.
The filesystem package must match the committed original-file manifest derived
from every integrity-checked lock archive: 4079 files including root package/lock,
plus the known npm bin links and validated generated npm lock metadata. An
alternate formatter cannot acquire original identity by declaring its own tree
hash. The original Node binary is independently pinned to the accepted version.

The namespace mounts these images into an empty private package filesystem using
read-only data mounts, then remounts its directory read-only. This protects both
file bytes and directory entries after capture. A verified installed directory
bind alone would not. Each launch reopens sealed descriptors with independent
file offsets so concurrent data mounts cannot consume one another's input.

The new sealed closure contract has explicit bounds: 8192 entries and 256 MiB of
captured input. Its private startup capsule is bounded to 1 MiB, 32768 arguments,
768 KiB of argument text and 8256 descriptors. These bounds cover the measured
locked closure (4077 archive files, 24,320,025 bytes, before runtime/libraries).
Legacy launch limits and the 64 KiB owner control/SCM protocols are unchanged.
Descriptor exhaustion, unavailable sealing, kernel restrictions, unsupported
bubblewrap or an unqualified platform refuse startup. There is no unsandboxed
fallback or relaxation of AppArmor, seccomp, resource budgets or timeouts.

## Transport and ownership

The additive contract is `sw-mcp/verified-original-execution/1`, endpoint
`POST /native/execution/v1`. Authentication and availability/capacity checks occur
before reading the body. An 8192-byte strict JSON preamble must finish within
five seconds and end in a newline:

```json
{"contract":"sw-mcp/verified-original-execution/1","catalogue_sha256":"<selected digest>","server_id":"filesystem","host_session":"<host>","child_authority":"<existing signed grant>"}
```

Following bytes are the unchanged MCP NDJSON stream. A preamble cannot supply an
executable, profile, library path, result descriptor or trust flag. The daemon
creates a fresh internal collector session, verifies existing child authority and
owns the original server's input/output pipes. The CLI is only a forwarder:

```sh
agentfw mcp-verified --id filesystem --host-session "$HOST_SESSION" \
  --child-authority "$CHILD_AUTHORITY" --home /operator/agent
```

The existing `AGENTFW_HOST_SESSION` and `AGENTFW_CHILD_AUTHORITY` fallbacks also
apply. Secrets are not included in retained evidence or diagnostics. The CLI
sends its native token only to a numeric loopback HTTP daemon URL, refuses
redirects and uses no proxy. It accepts no upstream command.

Response framing separates daemon control from arbitrary server payload. Every
frame starts with a type byte and a four-byte big-endian payload length, bounded
to 16384 bytes. Type 1 contains unchanged MCP bytes. Type 2 is a strict terminal
object with exactly `contract` and `complete`; success requires `complete=true`,
no later frame and clean EOF. Original MCP text cannot forge this control frame.
A terminal receipt is emitted after the existing owned cleanup path completes.
Connection loss or body I/O errors withdraw custody and signal bounded cleanup.
Four connections and one active connection per host are allowed. Uncertain owner
cleanup retains a bounded sticky host entry rather than claiming a safe relaunch.

The accepted persistent selected-server relay remains the execution engine: one
original process tree per selected connection, eight active calls/eight queued,
existing framing limits, native admission, classifier, Ask redemption, cancellation,
result inspection, cgroup ownership and cleanup. It does not spawn a fresh process
per call or multiply an existing tree's resource limit across calls.

## Call/result binding and replay

The qualified namespace PID 1 acknowledges the actual original child PID and start
generation through the inherited private channel. That namespace-relative child
identity is paired with the verified outside owner and pinned PID-1 generation;
a bare host PID is never the source of authority. Legacy PID-1 acknowledgement
remains unchanged for legacy launches.

Only the daemon's private launch context can create a `Dispatch`, after an admitted
native call and before writing that exact request to the owned original pipe.
Only reading a correlated original response can turn it into `OriginalResult`.
Both are private affine Rust values: no deserializer, public constructor or clone.
They bind current daemon instance, selected catalogue/closure, process and channel
generations, session epoch, native call/binding, host JSON-RPC ID, exact raw request
hash, original response hash/length and the existing call deadline.

The native result path removes the call before validation. It consumes this value
under the existing native session lock, verifies the exact current session/call,
owner and result, and then runs unchanged baseline inspection, taint/provenance
recording and audit-before-release. A failed completion cannot retain reusable
call authority. No TTL is extended. Cancellation, expiry, epoch replacement,
process withdrawal, daemon restart or mismatch refuse new custody. Concurrent
responses correlate by their own native and JSON-RPC identities.

Descriptive `execution` metadata appears only on receipts/audit rows produced by
this private path. Ordinary native/1 result handling cannot create it, even with
the same token, schema, response bytes or copied fields. Metadata is not a
redeemable attestation and cannot be sent back to obtain relief.

## SOU-109 and SOU-156 handoff

SOU-109 may later consume the private result at its current native result boundary,
after matching the current session/call/source/result and before its own separately
reviewed inspection decision. It must not trust serialized receipt/audit metadata,
install manifests or collector claims, and must retain baseline inspection or
existing-required refusal when private custody is absent. No parser/detector
implementation or production relief is part of SOU-155.

The optional `GitObjectWitness` shape reserves a domain contract, resolved object
kind (`blob`, `tree`, `commit`, `tag`), object ID and snapshot digest. SOU-156 owns
its independently reviewed producer and semantics. This PR issues no such witness;
`domain_witness` is always absent/null. A future witness cannot substitute a
result or confer generic content trust.

The SOU-155-side interface response to SOU-156 is recorded in the
[execution join agreement](SOU155_SOU156_EXECUTION_JOIN.md). The reserved diagnostic
shape above is not the final Git producer API. Production Git composition remains
disabled until the retained snapshot, requested/effective typed objects and common
private invocation are integrated and qualified together.

The current filesystem path accepts one strict complete original MCP frame and
inspects every content block, followed by structured content, without dropping
empty blocks or deduplicating equal text. Exact raw-frame custody binds their
identities, order, multiplicity and bytes together. Unknown envelope/result fields
are refused; this path accepts no additional result channel outside that frame.
A future multi-channel consumer must bind its complete ordered unique channel set
to the same one-use capability before using any optional attribution. Metadata or
a selected formatter text is insufficient. The current accepted inspection floor
and shared 32 MiB scan-work budget remain unchanged; exhausted evidence is an
incomplete refusal with a spent Call, rather than a partial successful inspection.

## Qualification and migration

Keep the legacy configuration and CLI until the explicit Linux runtime path is
qualified. Install the catalogue separately, pin exact bytes, enable liveness and
then select `mcp-verified` for the intended connection. Unavailable required
custody refuses that opt-in connection; it never silently downgrades it.

Focused development command:

```sh
gh workflow run sou79-resource-budgets.yml --repo SoupTeam/soup-wall \
  --ref codex/sou-155-daemon-verified-launch \
  -f prepared_focus=155 -f prepared_host=true
```

This uses actual original filesystem code in an owned ordinary-user Linux unit,
read-only source/runtime inputs, scratch-only writes, private loopback and explicit
per-original-tree budgets. Compiler/unit/Clippy results alone do not qualify its
actual launch. Every failed/incomplete attempt remains retained in
[evidence](evidence/sou-155-verified-execution/local-development.json).

Required native controls include useful original reads, exact request/response
identity, immutable executable/formatter replacement, identical-schema alternate
formatter refusal, concurrent correlation, forged/replayed/cross-session results,
Ask/cancellation/restart and denied zero effects with verified cleanup. Missing
controls remain gaps. Final current-main qualification, shared admission and merge
are owned by the team lead; a diagnostic success is not merge approval.
