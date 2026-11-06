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


### November 5 terminal cleanup ordering

All held-consumer termination branches now invoke the existing exact-run
`RunGuard::cleanup_waiter` before group termination: normal exit, timeout,
SIGINT, SIGTERM, daemon loss/restart and provider-environment failure.
Previously the cancellation branches could terminate first, and SIGTERM
ignored a failed namespace acknowledgement. The shared `stop_after_cleanup`
consumes the waiter once, checks recipient generation before withdrawal, and
still terminates/reaps the held child if cleanup returns an error or panics.
Neither failure can produce a successful stop confirmation for `RunGuard::finish`.
The existing cleanup worker retains its bounded daemon requests and six-second
namespace polling deadline; this does not introduce a new authority channel.

Two focused Windows process tests passed (one test-only child entry is ignored
in the parent runner and invoked explicitly by the witnesses). Actual file
writes prove the child remains alive during cleanup and stops afterward,
including cleanup failure and worker panic. Substitution cannot consume the
cleanup waiter, and replay is refused. This is not Linux namespace confirmation:
independent Linux execution is still required. The authenticated daemon/launcher
consumer registration and restricted-recipient handoff remain unfinished;
production purpose issuance/release stays unsupported and all six cases remain
open.

```sh
cargo test --locked -p agentfw --lib pilot_launcher::consumer::tests
```


### November 5 held-consumer registration

Independent review 5780668918 accepted the previous component at
`1f170f0a515fa120fd45ec2d7fce58ad61beb0ad`, with 26 executed Linux tests.

The next increment connects the existing launcher to a separate protected
`/native/held-consumer/v1` registration endpoint. It uses the same native-token
and verified loopback configuration as pilot control, with a 64 KiB request
limit and at most 32 retained host registrations. It does not accept purpose
intent or deliver any quarantined bytes.

After spawning the held Child, the launcher seals a second immutable manifest
containing its existing sealed run selection, the receiving PID/start time,
random Consumer generation and held descriptor. The daemon checks both sealed
manifests against the live same-binary pilot launcher, the direct child parent,
process group and start time. It rejects stale instances/registries/expiry,
retired source grants, foreign active host authority, duplicate host binding and
capacity overflow. Admission and retirement share the registration lock.
Registration failure takes the existing withdrawal/cleanup/stop path; the sealed
manifest remains owned by Consumer until disposal. Windows registration fails
closed because it cannot provide the selected Linux process proof.

This registers the original receiving process only. A stored registration is
not a reusable liveness, drain or purpose attestation. Atomic purpose spending,
source/call/result binding at quarantine selection, terminal acknowledgement and
a separately confined receiving process remain unfinished. The operator issuer
and payload release remain unsupported; the six before/after outcomes above do
not change. Independent Linux compilation and execution of the new registration
path are required before accepting this increment. No full/native qualification
or model calls were made.

Local Windows: `cargo test -p agentfw --lib consumer` executes five passing tests
(one existing grant test, two held-process tests, two registration controls),
with the child helper ignored in the parent runner. The new Linux-only witness
for sealed descriptor substitution, actual child generation/parent and exit is
not counted as executed on Windows. Initial local compilation found an unhandled
poisonable mutex result and an unqualified macro; both were corrected before the
passing run.

```sh
cargo test --locked -p agentfw --lib consumer
cargo check --locked -p agentfw --bin agentfw
```

The strict Clippy run also identified the earlier quarantine capture function's
argument count. Its inputs are now grouped in a borrowed `Capture` structure;
all 18 execution regressions passed afterward. Windows library Clippy with
`-D warnings`, binary check, and documentation validation (426 files / 1356
local links) passed. This refactor changes no capture condition or wire field.


### November 5 capacity correction (pending Linux review)

Independent review of eb944413 passed 29 Linux component tests, then found
that 32 terminated registrations exhausted capacity despite exact authority
withdrawal and child reaping. Live slots now have separate bounded terminal
replay custody (512 entries). Reclamation requires withdrawn/expired exact
authorities, no matching native sessions, confirmed cleanup for every admitted
namespace owner, and observed absence of both receiving PID and process group.
Unknown process/cleanup state retains capacity. Registration expiry alone does
not prove disposal. Tombstones remain until the sealed registration expires;
a full replay store fails closed rather than forgetting a generation.

The new Linux handler witness completes 40 actual child registrations through
the protected registration and stop handlers, checks replay refusal and verifies
that withdrawal alone cannot reclaim a live process. A second sequence fills
32 slots with reaped children but unconfirmed cleanup: the fresh registration
must fail until the protected cleanup finish handler confirms all owners.
Sealed manifests and real PID/parent/group observations remain mandatory.

Local Windows consumer tests: 5 passed, 1 subprocess helper ignored; library
Clippy with warnings denied passed. The new Linux-only sequence is NOT included
in that count. Local WSL enumeration failed, so independent Linux execution is
still requested with `cargo test --locked -p agentfw --lib consumer` using an
isolated target directory. This is a capacity fix, not purpose admission,
restricted-recipient delivery, or a correction of any of the six refusals.


### Atomic purpose withdrawal component - November 5

Review [5788292266](https://github.com/SoupTeam/soup-wall/pull/346#pullrequestreview-5788292266)
accepted the capacity correction at 204cd341 after 31 ordinary Linux component
tests, including the explicitly re-executed real-process helper. This was WSL
component evidence, not installed Ubuntu qualification. The next increment
keeps the operator issuer and all payload release unsupported.

`analysis_purpose::consume` reconstructs expected claims from private quarantine
custody and the live sealed launcher/child registration. It verifies the
separate purpose HMAC using the daemon key, current policy digest, source grant,
original response hash/length, invocation binding, epoch, host and child
generation. Neither an expected-binding JSON nor a copied receipt is authority.
The admission lock covers one-use ledger checks, existing exact-grant withdrawal
and quarantine spending. Purpose replay custody is bounded at 512; capacity or
foreign-binding errors do not partially spend purpose/authority. The shared
withdrawal helper is also used by the existing pilot-stop handler.

After commitment, the existing retirement path closes sessions and pending
approvals and audits withdrawal. Errors leave purpose and source authority
spent. An affine pending receipt can confirm only after rechecking retirement,
namespace cleanup custody and physical PID/process-group absence. It carries no
content, has no deserialize/clone constructor, and grants no fresh-reader
capability. A live child or unconfirmed namespace owner fails confirmation.
This selected-process observation does not prove rollback or exclude an escaped
process outside the observed group; a separately confined recipient and full
in-flight/transfer/restart boundary remain required before any result release.

The Linux helper now combines real sealed registration with the consume/confirm
component: tampered hash, replay, retired registration, still-live child,
unconfirmed cleanup and reaped-child confirmation. Its quarantine and signing
inputs are explicit test fixtures. The separate original-execution regression
checks binding reconstruction from actual private consumed-result custody,
foreign instance/policy refusal and retirement invalidation. No test fixture
is compiled into a production issuer. Windows tests cover transaction races,
capacity refusal, exact source retention and the existing stop-handler behavior.
Linux execution of the extended helper is requested independently and is not
claimed from a Windows pass.

Reproduction, each using an isolated Cargo target on Linux:

```sh
cargo test --locked -p agentfw --lib analysis_purpose
cargo test --locked -p agentfw --lib native::execution::tests
cargo test --locked -p agentfw --lib pilot_stop
cargo test --locked -p agentfw --lib consumer
```

The CLI remains unsupported. No HTTP consumption route, production purpose
mint, restricted recipient or payload handoff is enabled. All six refused cases
remain unresolved. Review this working withdrawal component before integrating
an issuer or enabling delivery.

Local validation: 7 purpose-contract/transaction tests, 18 original-execution
tests, 1 stop wire-contract test and 5 actual stop-endpoint regressions passed
(31 total). Library check, strict Clippy and documentation validation passed.
The first Clippy attempt flagged the extracted helper's complex return type;
named type aliases corrected it without lint suppression. A broad `revoke`
name filter matched two unrelated tests and is not included in this count.
The extended real-process Linux helper remains pending independent execution.


### Expiry across transaction lock wait - November 6

Independent review [5791131209](https://github.com/SoupTeam/soup-wall/pull/346#pullrequestreview-5791131209)
passed the 37 requested Linux component tests at b601bad0 but reproduced
expired-purpose consumption in three private contention runs. Those passing
component tests did not establish correct expiry handling.

Registration verification now occurs after the sessions, firewall and quarantine
locks are acquired. Purpose verification uses fresh wall time after custody
reconstruction, and the commit helper receives a fresh timestamp and rejects
expired purpose or registration before modifying any ledger.

The existing re-executed Linux lifecycle witness now holds the real firewall
lock while consume holds admission, releases it only after expiry plus 100 ms,
and requires refusal with purpose, both source authorities and quarantine
unspent. It covers a one-second signed purpose and a separately sealed short-lived
registration. The child and owner manifests remain real; quarantine/signing are
explicit test fixtures. A portable boundary test checks refusal at exact expiry
and preservation of existing ledger entries. Independent Linux execution of
these new contention controls is requested; a Windows pass cannot qualify them.

Issuer and payload delivery remain disabled. This fixes the reviewed transaction
boundary only; the restricted recipient and six benign outcomes remain open.


### Restricted recipient interface proposal - November 6

Expiry correction db84de69 was independently accepted in
[review 5791412713](https://github.com/SoupTeam/soup-wall/pull/346#pullrequestreview-5791412713):
37 distinct ordinary Linux tests, 18 expiry/contention refusals and three valid
consume/dispose/confirm controls passed. This accepts expiry handling only.

The next execution/IPC slice needs interface review before implementation, as
required by SOU-218. Source inspection found no existing zero-authority receiving
entry point that can be enabled unchanged:

| Existing component | Reusable responsibility | Missing receiving guarantee |
| --- | --- | --- |
| `pilot_launcher::consumer::Consumer` | Held child identity and physical stop | No new confined recipient or exact-source delivery channel |
| `pilot_host::isolate` | Clean environment and project configuration | Does not create OS namespaces; explicitly passes selected provider inputs |
| `sandbox::run_linux` | Required Linux user/network/PID isolation, capability drop, bounded collection | Mounts a writable workspace, accepts arbitrary program/args and has null stdin |
| `analysis_purpose::PendingWithdrawal` | Affine selected-process stop confirmation | Carries no response binding to a receiving lifecycle; confirmation returns unit |
| `native::quarantine` | Private complete bytes and provenance with original expiry | Terminal custody has no authenticated one-use transfer state |

Proposed reviewable increment, within the existing launcher and sandbox modules:

1. Add an internal restricted-reader profile to the existing sandbox machinery,
   not another launcher or classifier. No caller-chosen command, project mount,
   writable host mount, provider credential, native token, MCP socket or inherited
   descriptor. Required user/PID/network namespaces and capability drop stay
   mandatory. Private scratch is disposable and bounded; missing isolation refuses.
2. Initially run only a fixed local test reader over public fixture bytes. It
   returns a bounded digest/length acknowledgement to its owning parent, not raw
   text or executable instructions to the original agent. No model/API call or
   production quarantine bytes enter this first witness. A successful witness
   proves confined transport only, not useful semantic interpretation.
3. For later daemon wiring, retain exact source binding and original monotonic
   deadline in an affine withdrawal receipt. Register the fresh held child and
   executable/profile identity through the existing protected control boundary.
   Bind its distinct generation to daemon instance, quarantine ID, original
   response hash/length, call/epoch/policy and consumed purpose ID. Copied JSON
   identity, client assertions and the stopped source child cannot substitute.
4. Proposed handoff uses a parent-owned private anonymous channel with explicit
   descriptor ownership. The reader receives no bytes until current source
   custody, policy, expiry, spent purpose/authorities, selected-owner cleanup and
   actual recipient identity are checked together. Reserve transfer once before
   delivery; partial write, timeout, lost daemon or recipient exit is terminal,
   without retry into another recipient or restoration of source rights.
5. Do not return recipient stdout as ordinary agent/tool content. Derived content
   retains source taint and requires a separately reviewed receiving boundary.
   No output from this compartment authorizes a later tool action.

Required first runtime witnesses: actual network denial, failed project/home
read and host write, absent credentials/control descriptors, child escape and
cleanup, bounded output/time, substituted recipient and replay. Later connected
witnesses additionally cover partial delivery, restart, source/policy expiry and
an already running source effect. Preserve exact bytes and original labels in
all matched benign/malicious pairs; confined receipt is not attack refusal.

Decision requested from TL: approve the fixture-only no-network reader/profile
and anonymous-channel slice for the next working increment, and identify the
intended useful receiving surface. A local deterministic reader can validate
confinement; it cannot replace semantic interpretation. Reusing the current
Claude host would require explicit provider/egress and output-boundary design,
which this proposal does not approve or enable. No new model budget is requested.

This proposal is not an implementation or a six-case correction. Production
issuer, handoff and signature interpretation remain unchanged and unsupported.

### Public-fixture reader implementation - November 6

The fixture-only slice was approved in
[review 5796949598](https://github.com/SoupTeam/soup-wall/pull/346#pullrequestreview-5796949598)
and General at 13:45. The useful target is a separate analysis-only worker under
private review/control; provider/egress and semantic-output authorization still
need a separately reviewed design. This increment implements only the approved
local reader milestone, entirely under `cfg(test)` in the existing sandbox and
launcher modules. It does not introduce a production CLI, classifier or launcher.

The Linux parent starts a fixed libtest entry through required bubblewrap user,
mount, PID and network namespaces. It opens and hashes `/proc/self/exe` before
launch and binds that held inode using `--ro-bind-fd`. The owned file stays alive
through spawn; no parent proc path is resolved after entering the namespace.
Before any fixture bytes, the private-channel handshake must match that binary's
SHA-256 and show four namespace identities different from the parent. Only
read-only runtime library directories are mounted; project, home, `/etc`, tools
and provider/control credentials are absent. Root is remounted read-only, nested
user namespaces disabled, capabilities dropped and `no_new_privs` required.
CPU, address-space, descriptor, core and file-size limits are set before exec.
The system root-owned, non-setuid, non-group/other-writable `/usr/bin/bwrap` is
required; there is no PATH selection or unsandboxed fallback. This depends on the
trusted system runtime/library installation, not an independently pinned distro.

One anonymous socket is inherited as stdin. Stdout/stderr go to null. All other
descriptors are marked close-on-exec, then only the held executable descriptor
is allowed into bubblewrap for the mount. Bubblewrap consumes that descriptor;
the reader rejects all descriptors beyond stdio, including a deliberately
inheritable canary in the witness. The parent drops its Command and retained file
after spawn. The finite environment accepts bubblewrap's `PWD` only as `/` and
independently requires the real current directory to be `/`.
An affine in-memory **fixture ticket**, not a daemon grant or cleanup receipt,
reserves one exact generation/hash/length before writing, preserving its original
monotonic deadline. Mismatch and expiry consume that attempt. The reader returns
only 72 fixed bytes (generation, SHA-256, length), never source text. The parent
reads at most 73 bytes to detect overflow. No acknowledgement grants authority.

The required Linux witness does not skip missing isolation. It tests actual host
loopback denial against a listening socket; host file read/write denial with an
unchanged canary; absent home/workspace/config; read-only root; absent extra FDs
and environment; zero effective capabilities and denied nested user namespaces.
Eight lifecycle paths cover exact acknowledgement, partial/oversized ack, explicit
cancellation and deadline timeout with an actual `setsid` descendant holding the
channel, generation substitution, expiry and truncated source delivery. Every
path uses the existing held-Child stop/reap implementation. Reaped supervisor,
bounded channel EOF, unchanged canary and no accepted network connection are
required. The descendant must report successful `setsid` before the control is
counted. Portable tests cover source substitution, oversize, replay and exact
acknowledgement/deadline refusal.

Local Windows validation: two new protocol tests and two existing held-process
witnesses pass; three existing framed-reader tests also passed in the `reader_`
selector. Strict production-library Clippy passed. **Linux code has not been
compiled or executed locally**: WSL enumeration still fails. The following exact
head checks are requested from the independent Linux reviewer; do not infer a
kernel isolation pass from the portable tests:

```sh
cargo test --locked -p agentfw --lib sandbox::fixture_reader -- --test-threads=1
cargo test --locked -p agentfw --lib pilot_launcher::consumer::tests -- --test-threads=1
```

Remaining work is explicit: carry the authentic withdrawal receipt and original
quarantine deadline into fresh-recipient verification and one-use reservation;
prove connected source-owner cleanup, instance/restart, policy changes and
partial-delivery terminality; then review any production release and useful
semantic-output boundary. This test fixture ticket cannot substitute for those
proofs. The fixed public attack-shaped fixture is transported as inert bytes;
that is not an attack-Deny result. All six benign cases remain unresolved,
original labels/counts stay unchanged, and SOU-218/#346 remain In Progress/Draft.

#### Reader review corrections

[Review 5801800918](https://github.com/SoupTeam/soup-wall/pull/346#pullrequestreview-5801800918)
compiled exact `7107c287` on Linux but found early EOF in normal readiness.
The parent proc executable path was inaccessible after namespace entry, and
the environment check rejected bubblewrap 0.9.0's own `PWD=/`. The reviewer
confirmed an inherited held-descriptor `--ro-bind-fd` control works. The original
normal-path failure means the other seven lifecycle scenarios were not qualified;
two portable protocol tests and two existing cleanup tests passed independently.

The follow-up uses the pre-opened, verified executable described above and an
exact PWD plus actual-cwd check. A new portable regression rejects missing,
wrong or duplicate PWD, a mismatched real cwd and unexpected environment names.
Local portable validation does not qualify Linux descriptor consumption or the
eight kernel scenarios. Repeat both narrow commands above on the corrected exact
head before accepting this milestone. The failed `7107c287` evidence is retained.

### Connected custody-to-reader checkpoint - November 7

[Review 5806018111](https://github.com/SoupTeam/soup-wall/pull/346#pullrequestreview-5806018111)
accepted the fixture reader at `3279802e` on Linux/WSL2: four reader tests
(including all eight kernel subcases), two cleanup tests, fmt and strict
all-targets Clippy passed. The reviewer fixed post-reap ECHILD handling in
`209dfb39` and test-helper placement in `3279802e`. Those commits are incorporated.
The failed `e4702234` and `7107c287` runs remain historical failures, not passes.
General at 00:58 authorized continuing quarantine connection and the six cases.

This follow-up connects the existing components **under cfg(test) only**:

1. The existing `inspect_bound`/consumed `OriginalResult` path captures the full
   refused response, findings, provenance and taint in private quarantine.
2. Verified purpose consumption captures an affine private selector containing
   the exact binding, original monotonic deadline and digest of the entire
   retained record before spending and withdrawing source authority.
3. The receipt must confirm actual source-owner disposal before reader startup
   and again after confined readiness. No caller-supplied reader identity is used.
4. Under admission/firewall/quarantine locks, reservation checks current daemon,
   policy, epoch, exact retained record/content and original deadline. One attempt
   is terminal, including failure. The payload remains in custody; findings and
   taint are not erased. The transport bounds its deadline by the original call
   deadline and remaining purpose/registration lifetime, with a fresh wall-clock
   authorization check immediately before reservation.
5. Only the fixed verified reader receives bytes over its anonymous channel.
   Exact bounded acknowledgement and stop/reap/channel EOF remain required.
   Partial delivery or malformed acknowledgement cannot restore the receipt,
   source authority, purpose grant or transfer reservation.

The new Linux component parent `connected_quarantine_reader` executes a helper
with real sealed source registration and a real held source child. It invokes
actual consumed-result capture, purpose consumption/withdrawal and the existing
confined reader. Eight paths cover valid delivery, live source, unconfirmed
cleanup, original expiry, foreign daemon/restart, short/oversized acknowledgement
and truncated source. Negative cases require their specific failure code and
expected reservation state, so a setup error cannot masquerade as a pass.
The full retained record must be unchanged after every case. A portable custody
test additionally covers source/taint/epoch/policy/deadline substitution and
duplicate reservation after success or failure.

Limits: MCP runtime/admission and operator signing are explicit component
fixtures; this is not original-server execution or a production operator mint.
The helper transports an attack-shaped public response and returns only its
digest/length. It does not prove useful semantic delivery or attack-Deny.
The private source path has a 4096-byte ceiling and refuses larger inputs without
truncating the retained record. No source bytes enter ordinary responses/logs.
There is no production release route, provider or semantic-output authorization.
Actual daemon-loss/interrupted-future cleanup and production policy-transition
semantics still require qualification before activation. All six cases remain
open with the original frozen denominators.

Local Windows checks: 8 purpose tests, 18 execution tests and 2 quarantine tests
pass (28 distinct); strict agentfw all-targets Clippy passes. The broader quarantine
selector also executed three of those execution tests. New Linux connection code
has **not** been compiled or run locally; WSL remains unavailable. Independent
exact-source review and the following isolated-target Linux run are requested:

```sh
cargo test --locked -p agentfw --lib connected_quarantine_reader -- --test-threads=1
cargo test --locked -p agentfw --lib sandbox::fixture_reader -- --test-threads=1
cargo test --locked -p agentfw --lib analysis_purpose -- --test-threads=1
cargo test --locked -p agentfw --lib native::quarantine::tests -- --test-threads=1
cargo clippy --locked -p agentfw --all-targets -- -D warnings
```

Keep Draft/In Progress pending that review and the remaining useful-receiver and
six-case outcomes. No full/native matrix or new model run is requested.
