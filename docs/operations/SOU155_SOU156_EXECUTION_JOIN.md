# SOU-155 / SOU-156 execution join agreement

Interface response published by Nari-Ab on 2026-10-26 in PR #273, comment 6413442028. This records the SOU-155-side agreement; implementation and qualification are separate.

Subsequent accepted main `46921f8d84b56c379b73dd80688567a7a14dddd7` merged the
separate Git execution and inspection path in PR #277. This historical agreement
does not disable that accepted path. The SOU-155 filesystem capability remains
separate; composing Git into its metadata/extension contract is not enabled here.
Both private result paths retain their own validation, the shared inspection and
durable audit. Existing Git snapshot custody and restriction floors are preserved.

Olzhas, reviewed the SOU-156 proposal at 05014886c5270c0c0abb91304ca82d0d91c09d01 and the latest SOU-155 integration decision. From the SOU-155 side, I agree to these interface boundaries, with the following explicit mapping:

1. Snapshot: yes. Retain the private Snapshot/Arc<View> and its leases; mount the exact same sealed descriptors and generation for the admitted invocation. Hold/check it across pending Ask, execution and completion. No ambient repository fallback or claim of a full working-tree snapshot. Withdrawal is sticky.

2. Authority: SOU-155 owns the common one-use join. Its current private affine Dispatch -> OriginalResult path is the authority boundary; the Git adapter will receive only a borrowed opaque invocation context, with no public constructor, wire import, Clone or minting authority. Serialized profile/runtime/daemon/session/process references and the component's random slot remain correlation only. The adapter returns typed object/snapshot facts backed by the retained Snapshot; it cannot construct or renew the common result capability. Common consumption binds the current daemon, closure, process/channel generation, session/epoch, native Call/binding/deadline, request and complete result, and consumes once even on failed completion. These are the agreed integration requirements, not a claim that Git composition is already implemented or qualified.

3. Bytes/channels: agree to exact original request and complete response lines including LF, exact JSON-RPC ID, and your separate request/result hash domains. Keep the raw SHA-256 execution digest distinct from the component's domain-separated digests. The 65,536/1,048,576-byte caps are component eligibility limits, not changes to ordinary MCP or the shared scan budget. SOU-155's join must bind the complete ordered channel set from the actual consumer boundary: unique stable channel identities, ordinal, kind, byte length and exact bytes/digest, including empty channels and any channels outside the MCP frame. Duplicate identities, omissions, reordering and substitutions invalidate the join; identical bytes in distinct legitimate channels remain distinct channels. All channels keep independent policy/secret/taint/judge inspection. Preserve requested object and effective peeled target separately, with the bounded typed tag chain; blob/tree/unknown never become commit facts.

4. Lifecycle: retain the component's 8-slot/30-monotonic-second limits. Reserve the invocation slot after successful native admission/Ask redemption and before writing the original request; retain/validate Snapshot custody while Ask is pending. Effective completion deadline is the earlier of the existing native Call deadline and the component deadline; neither extends Ask/grant TTL. Cancellation, source withdrawal, expiry, owner loss, restart and uncertain cleanup revoke/spend the relevant capabilities; restoring old bytes or reusing a PID cannot revive them.

Production Git composition remains disabled pending reviewed integration and actual Linux qualification. Missing/unusable optional proof retains baseline; an invalid native Call/receipt refuses. Shared scan-work exhaustion remains incomplete Deny/not-inspected with a spent receipt and bounded audit, under the accepted 32 MiB budget. No raw-verdict override or SOU-109 attribution/relief is introduced by this agreement. This is interface agreement, not approval of PR #273's implementation or a production readiness claim.
