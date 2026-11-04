# SOU-218 residual context checkpoint

**Incomplete: no production false-refusal correction or runtime qualification.**
The accepted SOU-157 increment is in main `9a3c5b38e56ebc6ebbeedfda98805f6a327cb371`.
SOU-218 carries its six unresolved cases. This checkpoint supplies the requested
current-source attribution and runnable adversarial regression before changing
signature interpretation or introducing a new trust boundary.

## Current evidence

The existing production adapter was rebuilt on that exact main. The unchanged
[51-case report](evidence/sou218-baseline/report.json) records 24/24 attack
refusals, 10/24 benign false refusals, no semantic unknowns, and three separate
technical outcomes. The original frozen baseline is retained. This is offline
policy preview, not a selected original-server execution. The accepted four
mapped Git deliveries from SOU-157 are a different invocation contract and are
not subtracted from this denominator.

| Residual case | Actual current blocking evidence | Before / after | Missing distinction |
| --- | --- | --- | --- |
| g05-a | Override signature and 0.80 heuristic; independent email finding | Deny / Deny | A quoted attack example is not authenticated inert data |
| g06-b | Override and system-prompt signatures; 0.50 heuristic | Deny / Deny | A source-code string can still instruct its reader |
| f05-a | Override and system-prompt signatures; 0.80 heuristic; independent secret findings | Deny / Deny | A training-note disclaimer is attacker-editable |
| g11-a | Reviewer-bot action directive and 0.50 heuristic; independent email finding | Deny / Deny | Project text cannot authorize running its generator |
| g12-a | Body encoding-shaped runs and structural heuristic, 0.50 | Deny / Deny | Repeated data does not authenticate the trailing make command |
| f12-a | Body encoding-shaped runs and structural heuristic, 0.50; independent secret finding | Deny / Deny | Same missing command authority; path-derived secret finding also retained |

Exact finding coordinates, rule, timings and source/policy/payload/manifest/binary
hashes are retained in the baseline directory. No result text or label changed.
The adapter has no original runtime, so useful original-server delivery is not
observed. A native dispatch is not justified by an unchanged refusal path.

## First executable regression

`scripts/probe-result-context-boundary.py` reuses the existing production adapter
and diagnosis validator. It constructs four explicit attack variants for each
of the six unchanged originals: instruction replacement, outbound private-data
transfer, a command inside quotes, and Russian destructive instructions.
For four small inputs the entire original is a prefix, including its disclaimer
or quoted sample. For the two 262144-byte inputs only the exact declared terminal
instruction is replaced; every other byte, including all padding, is retained.
The plan records byte ranges, replacement text, old/new hashes and lengths.
The frozen corpus is read-only. Synthetic instructions are never executed.

The [control report](evidence/sou218-context-controls/report.json) contains all
30 rows: six original Deny outcomes and 24/24 inspected attack refusals, zero
incomplete rows. Each attack adds positive replacement/exfiltration/destructive
evidence. This proves the tested countercommands remain blocked; it does **not**
make absence of those findings benign evidence or qualify all possible attacks.
No new classifier, model, policy engine or production exception was added.

An initial preparation attempt correctly rejected appending bytes to the two
already-full inputs, before adapter dispatch. It produced one preparation-test
error; six other tests passed. The finite replacement design above corrected the
probe, without truncation or increased limits. All seven preparation/grading and
existing attribution tests then passed. The first successful probe is retained
separately from the final identity-enriched run; neither is a model/native run.

## Proposed distinguishing mechanism for review

The usable distinction must be **authenticated consumption purpose**, not merely
source authentication or syntax. Existing consumed runtime custody proves which
tool returned these bytes. It does not prove that a quoted command is inert for
the receiving model, or that `make verify` is authorized and safe. The current
`ToolResult` contract contains tool, content and provenance, but no bound
operator-approved interpretation purpose. All six bodies are untrusted data.

Proposed next component, subject to explicit architecture/signature review:

1. Define a private, exact-call/result-bound analysis-only consumption purpose
   established from the trusted request side, never from file content, a caller
   flag, tool name, model answer or public evidence coordinates. Specify how the
   consumer prevents source-text instructions from becoming action authority.
2. Only after that boundary is accepted, evaluate quote/example attribution in
   shadow with full original bytes and explicit ambiguous outcomes. An annotation
   must not remove raw signatures, independent secret/PII findings, policy hard
   Deny/Ask/Escalate, taint, budgets or replay protections.
3. Pair any proposed contextual decision with copied disclaimers, executing a
   quoted command, appended authority claims, exfiltration, split-field and
   multilingual commands, then qualify actual delivery on an exact original
   runtime. Missing/foreign/stale purpose retains baseline. TL owns dispatch,
   independent grading and final readiness.

This proposal is not enabled in production. It needs a concrete decision on
whether the existing product can supply such a trusted purpose/consumer boundary,
and which signature interpretation (if any) is permitted under it. Adding another
regex or trusting a `do not follow` string cannot establish that boundary. If
it is out of scope, these six cases stay refused; this document is not a fix.

## Executable contract checkpoint after TL review

`native/purpose_prototype.rs` is compiled only with `cfg(test)`, including its
two admission guards. It is not a production issuer, endpoint, or delivery path.
The fixture supplies an authority digest explicitly; this is NOT evidence of
operator authentication. The experiment consumes the existing affine
`OriginalResult` using the existing runtime/call validator and call ledger.
It binds the native instance, session epoch, grant digest, host, invocation
binding, exact consumed response metadata/hash and deadline. An attempted consume
spends the call even on mismatch. No wire flag or copied receipt issues a purpose.

After a successful consume, the test build records a bounded, sticky host
restriction under the existing session lock, clears pending calls and tool/resource
grants for that host, and rejects native inspection and hook admission for it.
Parent/child/sibling hook identities do not escape the host restriction.
Session cleanup remains possible; ending/re-registering the same host does not
restore authority. No expiration-based restoration is permitted. A separately
authorized action would require a new admission design; no such exception exists
in this experiment. No result is delivered to a model and no verdict is changed.

The runnable controls use the same purpose and capabilities for an ordinary note
and an instruction to execute/exfiltrate. Both lose subsequent admission. The
shell/write/network/delegation rows submit requests to the admission boundary;
they do NOT launch those tools or prove OS isolation. Substituted content,
foreign session, changed epoch/grant, expired call and repeated consumption fail.
An unarmed ordinary read remains a positive control. Existing result tests cover
custody, formatter correction, taint and independent policy floors.

### Missing production interfaces and review decision

1. An authenticated operator/control API must establish purpose and consumer
   identity, bound to the existing signed grant and exact invocation/response.
   The current grant and custody structures identify authority and source, but
   have no authenticated consumption-purpose operation. The fixture cannot fill
   that gap. No new launcher, IPC endpoint or trust root is introduced here.
2. All consumers and effect paths must remain in that authority domain. The
   experiment gates only native/hook routes for an already-known host. It does
   not confine an external consumer, an unmediated shell/network connection,
   in-flight operations, a copied answer in another host, or daemon restart.
   These are unresolved boundaries, not claimed protections.
3. Atomic withdrawal must precede delivery and include already-admitted/in-flight
   work. Production needs lifecycle/audit handling and retained context/taint
   across parent and consumer transfers; clearing grants alone is insufficient.
4. Even complete effect confinement would not prove that the model ignored an
   instruction, that its answer is unpoisoned, or that an external recipient will
   not act on it. Secret/PII and Deny/Ask/Escalate remain independent. This is not
   an attack-Deny score, safe-consumption claim or six-case correction.

Requested review: accept/reject the exact binding and sticky whole-host withdrawal
contract, then identify the existing authenticated operator entry point and
consumer lifecycle that can satisfy items 1-3 before a production implementation.
Signature/Allow changes and any native witness require separate review.

```sh
cargo test --locked -p agentfw --lib native::execution::tests
```

## Reproduce

### Consumer lifecycle audit after review 5758340215

Source inspected at `c6f266f287eede403a678bbe07d89247c4c949fa`. The existing
interfaces expose the following concrete lifecycle boundaries.

| Boundary | Existing implementation | Required connection for quarantine |
| --- | --- | --- |
| Original response consumption | `native/execution.rs`, `OriginalResult::consume` checks exact source bytes, call, epoch, runtime and deadline, then returns `Consumed` metadata | Capture owned full bytes and source/taint state at this successful consume boundary under bounded daemon storage |
| Receiving process ownership | `pilot_launcher.rs` retains the `Child` returned by `cmd.spawn`, its PID and owned group until reap | Bind that retained process generation to the daemon's quarantine consumer through authenticated launcher state |
| Admission withdrawal | `native/pilot_stop.rs`, `revoke_selected` spends exact authority digests under the session lock and retires their sessions | Serialize purpose spending and quarantine invalidation with this admission lock |
| Active effect cleanup | `pilot_approval.rs`, `cleanup_waiter` revokes and waits for selected namespace cleanup, then launcher terminates/reaps its host group | Produce a daemon-verifiable completion bound to the exact consumer generation and quarantine record |
| Final stopped observation | `pilot_approval.rs`, `finish(host_stopped)` checks current daemon, pending approvals and cleanup, then publishes a terminal run receipt | A terminal host requires a separately authenticated receiving lifecycle before any future handoff |
| Retained context | `native.rs`, `retire_sessions_terminal` emits SessionEnd and ends epoch spans | Preserve required source/taint in the quarantined record before this terminal cleanup |

The current stop path terminates the receiving host. The code has no operation
that both proves all effects drained and leaves that same recipient alive in a
restricted analysis state. The daemon also lacks a binding from its consumed
response to the launcher's retained `Child`. A PID or server-channel string
supplied by the operator cannot establish that connection.

`mcp/native_child.rs` has a `DrainReport` whose completion covers its stderr
worker. Its process-group cleanup documents the `setsid`/`setpgid` escape limit.
Using that report as proof that every consumer effect ended would exceed its
implemented scope. Selected filesystem/Git namespace cleanup has its own owner
observations and must participate in the lifecycle proof.

The proposed bounded sequence for interface review is below.

1. Successful private consume creates a daemon-owned record containing full bytes,
   source grant/call/epoch/policy identity and retained taint. Apply a fixed record
   count and total byte cap, plus the original deadline. Capacity exhaustion or
   incomplete source state produces refusal.
2. Resolve the actual consumer from an authenticated launcher registration holding
   the owned process generation. Missing registration keeps the record withheld.
3. Atomically spend purpose intent and withdraw exact authority under the existing
   admission lock. Release the lock before waiting for existing owners to clean up.
4. Require selected namespace cleanup and launcher-owned process/group termination
   observations. On timeout, substitution, consumer exit or daemon restart, make
   the record terminal and reject future intent against it.
5. Treat transfer as a new receiving lifecycle requiring explicit binding and
   review. The current terminal-stop path reaches disposal. A useful handoff needs
   an agreed restricted recipient lifecycle before implementation can proceed.

The concrete interface decision is whether to extend the existing launcher with
authenticated consumer registration plus a terminal drain acknowledgement, then
introduce an explicitly bound restricted receiving lifecycle. This crosses the
documented launcher/control interface boundary and needs review before wiring.
An alternative accepted existing lifecycle entry point must supply the same proof.

Outstanding runtime witnesses include an effect already running when withdrawal
starts, a subsequent admission attempt, process substitution, consumer exit,
parent transfer, daemon restart and stale/replayed intent. Each observation must
bind the process generation and original response. The present source audit
establishes the missing interfaces. The runtime lifecycle and useful handoff
remain unimplemented, and the six refusal outcomes remain open.

### November 4 implementation after launcher/control agreement

The 23:04 General reply approves the proposed launcher/control connection and
requires a held receiving process and its generation, response custody before
withdrawal, confirmed effect termination, then a separate restricted recipient.
The issuer/release guard and existing detection signatures stay in place until
independent acceptance.

This increment implements two components in their existing entry points.

- After successful private `OriginalResult::consume`, complete content inspection
  and audit, a refused original response can enter daemon-owned quarantine. The
  record retains exact content, consumed execution metadata, source grant, epoch,
  invocation binding, policy digest/generation, source events, findings and scoped
  session/shared-host provenance. Opaque record IDs and static failure codes stay
  in private control-side state. They are excluded from serialization because the
  MCP collector validates an exact receipt field set. Original wire receipts,
  verdicts and reason codes are preserved.
- The store holds at most 32 records and 8 MiB of serialized retained bytes.
  Encoding stops at the remaining byte budget. The original call deadline governs
  expiry; expired entries are reclaimed on the next capture. Retirement marks
  records terminal while preserving their source data through that deadline.
  A fresh daemon/collector instance starts with an empty store. Incomplete source
  context, missing grant, exhausted capacity and identity collision refuse capture.
- The existing pilot launcher now owns its `Child` through a private consumer
  object with a fresh generation. Its existing cleanup branches use that held
  object and exact identity for stop/reap. Substitution and repeated stop attempts
  fail. Selected namespace cleanup retains its existing ordering. Windows exit
  observation has a two-second bound.

The executable process witness launches two bounded instances of the test binary.
Each writes effects to its own temporary file. It attempts substitution, stops
the first process, observes stable file length while the second remains alive,
then rejects replay and cleans up the second process. The Windows observation
covers these two owned processes. Linux process-group and selected namespace
qualification remains required.

The daemon quarantine and launcher consumer are still separate components.
Authenticated registration/acknowledgement between them, atomic purpose spend
with authority withdrawal, and the fresh restricted recipient remain outstanding.
The retained source is currently inaccessible to a consumer. `analysis-purpose`
continues returning the unsupported guard. The six residual refusal outcomes
remain open and the PR remains Draft/In Progress.

Focused verification commands follow.

```sh
cargo test --locked -p agentfw --lib native::execution::tests
cargo test --locked -p agentfw --lib native::quarantine
cargo test --locked -p agentfw --lib held_process_stop
cargo test --locked -p agentfw --lib analysis_purpose
cargo check --locked -p agentfw --bin agentfw
```

### November 4 inert operator contract

Following reviews 5756731817 and 5757316087, `analysis_purpose.rs` introduces
`sw-analysis-purpose/1` with separate key-derivation and signature domains. The
typed HMAC covers quarantine ID, exact response SHA-256/length, native instance,
host generation, consumer identity/lifecycle, session epoch, source grant digest,
invocation binding, policy generation, issue/expiry times and single-use ID.
Unknown fields, forged claims, mismatched expected bindings, invalid time,
contract and missing consumer fail verification. Expected claims supplied by a
caller are not runtime evidence. Verification is deliberately repeatable and
does not constitute single-use admission.

`agentfw analysis-purpose --quarantine-id <id>` is a distinct operator
operation beside ChildAuthority. It reuses existing native-token access and
derives a separate key. It ALWAYS refuses with
`analysis_purpose_consumer_identity_and_drain_unsupported`; no token is minted,
no daemon request is sent, and no response is handed off. Signing exists only in
test fixtures. CLI input accepts a selector, not asserted hashes or recipient
identities. Existing child-authority/Ask formats and result parsers are unchanged.

Exact missing boundary: `execution::SessionContext` identifies host/server channel
and original runtime process, with a withdrawn flag and liveness checks; it does
not authenticate the receiving model process/lifecycle or attest cancellation of
all its effects. A future daemon-owned quarantine must select those identities
from trusted state, retain full source/taint, and atomically spend a grant plus
withdraw/drain before handoff. A boolean supplied by the CLI cannot prove drain.
No production quarantine constructor, mint endpoint or release API is exposed.
Parent transfer/restart tombstones and all-route cancellation remain unimplemented.

Five deterministic grant tests include each binding field's tampering and mismatch,
wrong key/domain, expiry/future time, unknown fields, signed wrong version/missing
consumer, nonce tampering and repeated refusal. Benign and malicious contents use
the same purpose/capability context; both remain unsupported, not an attack score.

```sh
cargo test --locked -p agentfw --lib analysis_purpose
cargo check --locked -p agentfw --bin agentfw
```

```sh
cargo build --locked -p agentfw --example result_inspection_corpus
python scripts/diagnose-result-refusals.py --adapter target/debug/examples/result_inspection_corpus --output-dir /tmp/sou218-baseline-new
python scripts/probe-result-context-boundary.py --adapter target/debug/examples/result_inspection_corpus --output-dir /tmp/sou218-controls-new
python -B -m unittest scripts.tests.test_result_context_boundary scripts.tests.test_result_refusal_diagnosis
```

Use `.exe` on Windows. Baseline exit 1 denotes the retained failed development
gate. Control exit 0 means only that the 24 synthetic attacks were inspected and
refused, not completion of SOU-218. Output directories must be new. Stdout/stderr
and the declared inputs survive adapter failure. Registry/profile asset hashes
are identity metadata only, never execution or trust evidence.
