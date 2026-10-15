# Constrained MCP file creation (SOU-54)

The Linux native MCP broker can create **one new direct child of an explicitly
approved workspace root**. The fixed tool is `create_file`; its arguments are
exactly `{ "path": "new.txt", "content": "UTF-8 text" }`. Original arguments and
JSON-RPC identifiers remain unchanged. The discovery MCP child is started to
provide its manifest, but receives no tool invocation for this operation.

This is a bounded operation executor, not containment of arbitrary MCP server
code. The server must still be operator trusted for startup/discovery. Ordinary
unprofiled tools retain their existing behavior. No model, external destination,
provider credential or general filesystem writer is introduced.

## Operator authority and supported scope

An operator-installed native registry must select the exact `create_file` schema,
`side_effecting` baseline, resource profile, classifier revision, workspace and
one canonical absolute allowed destination. Neither a matching name nor tool
metadata can enable writing. The reviewed profile uses `/path`, `kind: path`,
`allow_missing_leaf: true`; aliases, optional/default selectors, multiple targets,
network selectors and alternative action classes are unsupported.

The resource policy's closed execution declaration is:

```json
{
  "operation": "create_file",
  "action": "write",
  "max_content_bytes": 4096,
  "executor_profile": "sw-native/create-file/linux-root-child/1"
}
```

`executor_sha256` is SHA-256 of the UTF-8 executor profile string above. It denotes
the reviewed implementation profile; it is **not** a binary attestation. Record
the built binary SHA separately. `classifier_sha256` is the exact installed
classifier script SHA. The path schema requires a string with `minLength: 1` and
`maxLength: 4096`; content is a string with `maxLength: 4096`; both are required
and additional properties are forbidden. The bound deliberately remains within the real rule baseline's inspected text limit; an unknown classifier result is not bypassed for a larger body. The executor additionally limits the
**UTF-8 byte count** to 4,096, regardless of JSON character count. The leaf name
is at most 255 UTF-8 bytes. Existing canonical hashing rules apply.

The collector uses `sw-native/resources/2` for creation and binds operation,
action, profile, byte limit, workspace identity, destination, original arguments
and content digest. The daemon rederives authority from actual arguments. Legacy
resource contracts cannot downgrade a creation call. A permission digest alone
is not an invocation grant; the ordinary native call and result gates remain
required.

Only an exact known `write` classification can enter the specifically installed
constrained-write policy path. Classification still supplies evidence rather than
execution approval. Deny and unconfirmed Ask stop before the executor. Unknown,
mixed dangerous actions, invalid scores, stale revisions, unauthorized resources
and unsupported profiles remain refused. This does not implement the separate
SOU-48 approval feature or authorize a generic write tool.

Supported execution is Linux on local filesystems with the required anonymous
staging, publication and synchronization semantics. The initial filesystem set
is ext4, XFS, Btrfs, tmpfs and overlayfs; actual syscalls must also succeed. macOS,
Windows, unsupported filesystems, unavailable `/proc` descriptor publication or
unavailable `O_TMPFILE` fail closed, with no named-file fallback. `workspace` and
`cwd` must resolve to the same root. Nested paths, traversal, ambiguous spellings,
missing parents, symlinks, existing files, directories, hard links and special
files are refused. The executor never overwrites, truncates or appends.

## File effects and result release

The broker pins the root directory inode before admission. It checks root
identity and destination absence before preparing or publishing, creates an
unnamed `O_TMPFILE` with mode `0600`, writes exact UTF-8 bytes, synchronizes the
file while monitoring client cancellation or overlap, then atomically links the completed inode without replacing a destination.
Cancellation or unsupported overlap before publication discards only the anonymous inode. It finally synchronizes the directory. There is no named staging entry to leak or
to remove another operation's file. Concurrent attempts for the same destination
can publish at most one file; the other attempt reports failure.

Observed root-path substitutions before publication are refused. A concurrent
rename after the final check cannot redirect the pinned descriptor to a
replacement root inode. Authority remains the originally approved root inode;
this is not a guarantee against an operator with the same host UID relocating
that inode. Keep the workspace and registry under the intended operator's
control; this feature is not protection from arbitrary same-UID host code.

Success returns a text JSON receipt with `success`, `created`, `committed`, the
original `path`, `bytes_written`, `content_sha256`, `file_synced` and
`directory_synced`. The contents are not echoed. Failures distinguish anonymous
staged bytes from committed bytes. A directory-sync or completion/result-release
failure can occur **after publication**. Such a failure is not proof that nothing
ran. A committed destination stays present even if its receipt is withheld;
result withholding cannot undo filesystem effects.

Audit evidence records bounded correlation/effect metadata, not raw content or
paths. Native refusal reasons and client-visible receipts retain their different
meanings. In particular, an Ask/Deny at invocation is distinct from an allowed
operation followed by failure or withheld output.

## Reproduce the bounded local verification

Use a clean exact source revision on Linux and an Agent binary built from that
revision. No running Agent or existing home is required. The driver creates and
removes its own private home, registry, policy, files and local daemon:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 scripts/verify-sou54-create-file.py --run \
  --repo "$PWD" --agentfw "$PWD/target/debug/agentfw" \
  --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou54-create-file-results.json
```

The output must be fresh. Without `--run`, the command reports the planned matrix
and starts no processes. On unsupported operating systems it records incomplete
positive acceptance and exits `2`; it does not report an absent Linux capability
as a pass. Exit `1` denotes a witnessed failed check; `2` denotes incomplete
source, environment or setup evidence. The report retains the exact source,
binary/configuration/script digests, raw synthetic call/result frames, classifier
and native audit correlation, per-call latency and independent workspace/outside
file type/mode/link/content hashes. Agent tokens and private homes are not
retained. It must report successful owned-resource cleanup.

The 26-case matrix includes relative/absolute UTF-8 creation, empty content, the
byte limit, multibyte overflow, existing files/links/FIFOs/directories, unsupported
nested/missing-parent/traversal/outside/unlisted destinations, native and
classifier Ask/Deny, mismatched operator server ID and an unset workspace variable
with a collector cwd outside the approved root, ambiguous `./leaf` and absolute
double-slash spellings, 70 consecutive existing-target failures followed by useful
same-session read, and committed creation whose result is withheld. Each case
requires a useful read in the **same** native session and a clean MCP EOF/closure.
The independent discovery child creates its ledger before startup and records any
unexpected forwarded tool call. An empty child ledger alone cannot pass: exact
file effects and released bytes must also agree.

Controlled destination/root replacement races, authority substitution and
injected partial-write, before-publication, post-commit directory-sync failures are exercised by the native Rust suites. These are explicitly
separate evidence from black-box stdio observations. To include an already-built
native test executable, supply `--native-test-binary PATH`; it must contain actual
`create_file` tests, including at least one passed test, and records its raw test outcomes rather than silently passing an
empty test selection.

```sh
cargo test --locked -p agentfw --lib create_file -- --nocapture
cargo test --locked -p agentfw --test native_endpoint create_file_v2 -- --nocapture
cargo test --locked -p agentfw --lib sou54_ -- --nocapture
cargo test --locked -p agentfw --lib mcp::input::tests:: -- --nocapture
python3 -m unittest discover -s scripts/tests -p 'test_sou54_create_file.py' -v
```

[The Linux CI fixture](../../.github/workflows/mcp-create-file.yml) retains the
matching build/test logs and sanitized JSON report. False interruptions refer to
the four deliberately useful permitted creation cases in this synthetic matrix;
these are not held-out classifier error rates. Latency samples include the
scripted client, local debug binary, classifier, native policy and filesystem.
They are not a production throughput, durability, RTO or general host benchmark.
Independent review and the accepted exact-source checks are required before
closing SOU-54; a local fixture is not product release acceptance.

## Actual native admission race and replay checks

A second [actual stdio driver](../../scripts/verify-sou54-create-races.py) uses the
same production collector, classifier, policy, daemon and constrained executor.
Its owned loopback proxy forwards the collector's real authentication header
without retaining it. It never manufactures an Allow receipt. For two deliberate
substitution controls it changes only the native request's destination or content
while preserving the original execution binding; the **real daemon** must Deny.
Other cases hold an authentic upstream Allow before the collector receives it.

```sh
python3 scripts/verify-sou54-create-races.py --run \
  --repo "$PWD" --agentfw "$PWD/target/debug/agentfw" \
  --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou54-create-races-results.json
```

The nine cases cover destination substitution, content substitution, replacing
the root pathname after genuine admission, two admitted MCP sessions racing for
one target, queued unsupported overlap, queued cancellation, a batch, a
replayed host call ID and a real OS-limited partial write. Root movement and replacement-canary setup are explicitly
labelled **fixture mutations**. Original-root, replacement-root and outside-file
snapshots are retained separately; the original root is restored only after the
refusal and snapshots, before its same-session useful read.

The concurrent case must publish exactly one complete file belonging to one
submitted invocation and record the losing operation honestly. Both independently
admitted sessions must remain useful. Queued overlap/cancellation is deliberately
unsupported: the original native session must end before the held Allow reply is
released, with no invocation or protected reply delivered. Batch and replay also
close their transport explicitly. Recovery in those protocol-refusal cases uses
a **fresh session**, not a false same-session continuation claim. An already
committed first call in the replay case remains an effect; the replay must add no
second effect.

The report keeps raw synthetic native bodies/replies with their byte digests,
real daemon decisions, client release bytes, independent child ledgers, execution
records and file witnesses. Every proxy handler, MCP process, local daemon and
private fixture must finish before a pass. This controls selected race orderings;
it does not establish all scheduling interleavings. The Linux workflow runs both
stdio drivers as required checks; the pure Python grader controls validate how
incomplete, fabricated or contradictory observations are rejected.

The [2026-10-15 bounded Linux evidence](evidence/MCP_CREATE_FILE_2026-10-15.md)
records the exact tested source and binary, original red witnesses, all 26 stdio
and eight race outcomes, false interruptions, latency and explicit limits.

The `partial-write-os-limit` case launches only its owned collector through a
[small Linux fixture wrapper](../../scripts/fixtures/limited_create_file_agent.py).
Before executing the unchanged Agent binary, the wrapper sets both
`RLIMIT_FSIZE` limits to 2,048 bytes and ignores `SIGXFSZ`; its actual launch
settings and source SHA are retained. A 4,096-byte ASCII invocation passes the
real classifier and authentic native Allow, then the real filesystem write must
fail after 2,048 anonymous staged bytes. The receipt and broker record must agree
on `stage_write_failed`, zero committed bytes and `committed: false`. The error
completion must pass real native result inspection before delivery. Independent
workspace/outside snapshots require no destination, named staging leak or other
change, followed by a useful read in the same session and clean EOF.

Only this fixture collector gets the OS limit. Its stderr uses a pipe drained by
the parent into a parent-owned regular log, so diagnostic logging is not itself
subject to the collector's 2,048-byte limit. The bounded drain must reach EOF and
join before acceptance. No production fault hook or global file-descriptor count
is involved. The discovery child's ledger remains empty and its bounded discovery
records remain below the file-size limit.
