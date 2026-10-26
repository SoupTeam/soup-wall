# Unposted SOU-156 handoff to the SOU-155 owner

**Draft for review; not sent. No agreement or owner approval is claimed.**

Proposed message to Nariman / SOU-155:

SOU-156 reproduced an exact original Git MCP ambiguity: a commit and a raw blob
with different OIDs/kinds return byte-identical original responses. We are
building local typed facts from the accepted sealed shallow `.git` view and a
bounded one-use invocation/result ledger. This authenticates no process/runtime
and enables no production inspection relief. SOU-155 keeps ownership of daemon
launch, runtime closure verification, channel custody and IPC.

Please review the concrete component contract in
[GIT_OBJECT_WITNESS.md](GIT_OBJECT_WITNESS.md). Its schema and runtime/generation
fields are proposals, not an agreed wire protocol. Four decisions are needed:

1. Can the daemon pass/retain a private `Snapshot` capability and mount **that
   same retained sealed view**, with no ambient Git object fallback? The adapter
   reuses `shallow_view::View` and inherits its source withdrawal and limits;
   this is a `.git` object/metadata image, not a full working-tree snapshot.
2. Which opaque identifiers does your execution owner supply for daemon,
   session, process generation and invocation? The provisional fields are
   nonzero 32-byte values. The local component slot is not a competing daemon
   authority; final identity/custody must come from your reviewed boundary.
3. Can we freeze the exact digest boundary as the original tools/call request
   line and original MCP response line **including LF**, before any inspection,
   wrapping or reserialization? Limits are 65,536 and 1,048,576 bytes, with
   explicit separate request/result hash domains and original JSON-RPC ID.
4. Which lifecycle component owns expiry, single use, cancellation, restart and
   cleanup? Local pending/completed slots currently have a provisional bound of
   8 and a 30-second monotonic lifetime; this must not alter Ask/grant policy.
   Production composition stays disabled until the daemon-controlled
   launch/channel binding and this handoff are independently reviewed.

First witness scope is `git_show` under existing profile argument grammar.
Requested object kind and effective target remain distinct, especially for tags;
unsupported packed witnesses and tag-to-blob/tree cases cannot become commit
evidence. Existing profile identities/defaults and original schemas, arguments,
errors and result bytes are preserved. No SOU-109 parser/policy changes are part
of either the proposed Git component or this handoff.
