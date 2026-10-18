# Managed policy changes during native MCP sessions (SOU-82)

This contract connects [signed managed delivery](MANAGED_AGENT_POLICY.md) to
[native MCP admission](MCP_STDIO_ADMISSION.md). Enrollment, signing keys,
approved revisions, group rollout APIs, installed profiles and executor
permissions keep their existing interfaces. A policy update never grants a
tool absent from the installed registry or broadens a child authority.

## Identity and ordering

The effective identity is `(revision, deployment_sequence, policy_sha256)`.
Sequences increase per enrolled Agent, including rollback to identical YAML.
Native receipts and audit records include `managed_policy` when an accepted
managed policy exists. The receipt describes the evaluator that made that
decision; it is not an independent permission to bypass the collector.

Trusted collectors negotiate `policy_transition: "sw-managed-native/1"` on
`session_start`. Both daemon and collector must use the same protected Agent
home. `managed-native-boundary.lock` is a persistent regular file in that home;
do not delete, rename or replace it while either process is running. Symlinks,
Unix hard links/FIFOs and Windows reparse points are refused.

| Boundary | Policy and authority behavior |
| --- | --- |
| Queued selected-server request | No execution receipt is issued until promotion. Admission evaluates the current policy and existing session/host risk. |
| Call admission through actual stdio write | Collector holds a shared OS file lock. Managed activation cannot overtake an admitted request before its complete write. |
| Brokered local resource executor | The same shared boundary covers admission, bounded execution, inspection and reply. An activation may wait for that bounded operation to finish. |
| Dispatched original-server request | The dispatch lock is released after the complete request write. The server may already have acted. A policy update cannot undo that action or retract bytes already written. |
| Result/context after a policy change | Daemon re-evaluates the original action against the current policy and retained shared-host risk, without reusing old Ask approval. Ask/Deny spends the old receipt and withholds its content. Allowed actions still undergo normal result inspection and provenance accounting. |
| Result inspection through host write | Collector holds a new shared lock until the complete host write. Activation cannot overtake an inspected result that is still being released. |
| Ask continuation | No lock is held while waiting for operator input. Activation increments the durable approval epoch. An earlier approval cannot be redeemed under the new sequence, even if the YAML is identical. |

Activation takes an exclusive nonblocking file lock, then the native session
mutex, then the evaluator mutex. While holding these, it checks compatibility
and increasing sequence, invalidates old approval authority, persists the
verified signed bundle and swaps the policy in the existing evaluator.
**The evaluator swap is the local policy linearization point.** Persistence
precedes it; the applied ACK follows it and reads back the active identity.
Collector boundaries remain excluded throughout that critical section.

If a collector owns the boundary, activation remains pending and health reports
`managed_transport.state: activation_pending`. It is neither an applied ACK nor
a rejection. A later poll retries. Reader fairness is not guaranteed: sustained
traffic or stalled writes can delay activation; the existing bounded I/O and
executor timeouts still apply. OS locks are released when their owning process
dies. A daemon restart refuses restoration while a surviving old collector
still holds the boundary; retry startup after that bounded operation exits.

This is a trusted local collector contract, not attestation against a malicious
same-user process with the native token or write access to the Agent home.
Legacy collectors cannot join an already managed evaluator. Existing legacy
sessions prevent first activation until they close; upgrade collectors and
daemon together. Do not delete the lock or clear risk to force activation.

## Risk, rollback and recovery

Activation mutates the policy in place. Native sessions, shared host identity,
retained taint, incomplete-history floors and constrained authority survive.
A new collector does not clear shared-host risk. A daemon restart changes its
native instance identity; old collector sessions/receipts fail closed and
previous child proofs cannot be silently reused. Existing durable host-history
recovery remains responsible for retained/lost history after restart.

Invalid signatures, digests, audience, sequence or policy YAML never replace the
last accepted policy. A network outage also leaves it active. A verified cached
bundle restores the accepted evaluator before serving after restart. A rollback
is an approved earlier revision issued with a **new higher sequence**, not a
restored old receipt, database counter or signing envelope.

Distinguish four observations:

1. Console issued/delivered records identify a candidate.
2. An authenticated applied ACK identifies the Agent's active evaluator at ACK
   time; it does not attest that every server process has stopped earlier work.
3. Agent `/health`, native receipts and native audit identify current evaluation.
4. Independent receiver/filesystem/process evidence establishes actual execution
   and release for a particular operation.

Applied state is per Agent. Neither these locks nor group rollout ACKs provide
whole-fleet atomicity. Hook responses and external host execution retain their
existing separate trust and fail-open boundaries. This work does not add
selected-server Ask prompting, new executors or live-model efficacy evidence.

## Operator procedure

1. Install matching daemon/collector versions with the existing protected home,
   reviewed registry/profile and verified HTTPS/pinned issuer configuration.
   Keep `enforce: true`. Close legacy collectors before first managed activation.
2. Create and approve an Agent revision using the existing Console API. Record
   its exact YAML digest, target Agent and issued sequence. Deploy it.
3. Compare Console state with `/health` and native receipt/audit identity. If
   `activation_pending`, inspect the owned collector's current bounded operation;
   do not call the deployment applied or forcibly replace its lock file.
4. Exercise an exactly identified supported operation, recording tool/schema,
   arguments, profile and independent execution observation. Treat previously
   dispatched work as potentially executed, even if its result was withheld.
5. To roll back, deploy the approved previous revision with `rollback: true`.
   Require the new sequence, matching applied ACK, active identity and useful
   runtime control. Old Ask approvals require fresh operator review.
6. During outage, continue only under the last accepted policy and existing
   authority. After daemon restart reconnect with newly bound collector
   sessions; do not replay old receipts or child proofs.

## Reproduction and evidence

`.github/workflows/managed-policy-tls.yml` prepares the already pinned original
filesystem/Git runtimes, builds the actual Console and Agent, runs the existing
HTTPS transport controls and then runs this dedicated driver for both databases:

```bash
python3 -B scripts/managed-native-transitions.py --backend sqlite \
  --agentfw target/debug/agentfw --console target/debug/llm-firewall \
  --node /owned/node/bin/node --npm /owned/node/bin/npm \
  --git /owned/git/git --git-launcher target/debug/agentfw-git-sandbox \
  --bwrap /owned/bwrap/bwrap --expected-commit "$(git rev-parse HEAD)" \
  --output /owned/new-sou82-sqlite-evidence
# Repeat with --backend postgres and a different new evidence directory.
```

Use disposable Linux x86-64 with Docker, the accepted bubblewrap runtime and
Python dependencies shown in that workflow. No sandbox relaxation, provider key
or operator database is required. Draft PR qualification can use manual workflow
dispatch; marking a PR ready merely to run these checks is unnecessary.

The versioned report retains source tree/commit, binary and original profile
identities, ordered issued/active/ACK observations, responses, FIFO reader
witnesses, Git kernel-open counts and cleanup. Failure writes a failed report;
missing prerequisites or checks never count as a pass. Private homes, credentials,
signing material and database dumps are not artifacts. Native Ask controls use
the existing legacy registry API and are labeled separately from actual original
server execution. The deterministic relay test stalls the physical dispatch and
result writes; a separate subprocess test checks lock release after process death.

Review the exact run's artifacts and source SHA before accepting its evidence.
This fixture measures local enforcement under controlled calls, not production
deployment success, a fleet-wide transaction, or behavior of a live model.

The [retained qualification record](evidence/sou82/qualification.json) identifies
the passing SQLite/PostgreSQL run of source `3163105` and earlier failed controls.
Its [unaltered sanitized archive](evidence/sou82/acceptance-3163105.zip) contains
both full reports and original collector logs. The record pins the archive and
report SHA-256 digests; evidence-only follow-up commits do not change the measured
runtime source. Each database passed all 16 controls, including a calibrated
positive Git-open observation followed by zero opens for the denied call.
