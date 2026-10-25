# SOU-83 — Experimental original filesystem create-only profile

The explicit opt-in profile is `sw-mcp/filesystem-create-only/1`, reusing the
pinned ORIGINAL `@modelcontextprotocol/server-filesystem@2026.8.31` upstream
identity, discovery, schemas and output. The separately selected original
read-only profile remains unchanged. Only original `write_file` has additional
authority. Original `edit_file`, `move_file` and `create_directory` remain
unsupported.

A create request must carry **exactly** `path` and `content`.
`path` is `/workspace/<single-nonhidden-ASCII-leaf>`, content at most 4096
UTF-8 bytes, with no aliases, parents, extra fields, overwrites or append.
At most one create can be queued/running at once. The tool's native registry
entry must explicitly declare `side_effecting`, the exact versioned profile,
untrusted result provenance and no egress. Read-only tools keep read-only
authority. No classifier means fail closed. Unknown, mixed or understated write
semantics, Deny and unsafe/missing native receipts do **not** publish files.
An exact known write can resume a native policy Ask only with the explicitly
enabled single-use approval described below.

The exclusive create slot also covers a cancelled producer's bounded cleanup
and an anonymous staging worker whose async waiter has ended. Spending a
native grant or removing its logical call cannot free that slot early. A new
create receives the existing busy refusal until cleanup finishes; read-only
continuation remains available.

## Actual create path (opt-in only)

1. Before admission, the collector pins the *actual* owned workspace directory
   inode; substitutions must fail instead of opening the replacement path.
2. The installed read-only server never receives `write_file`. After explicit
   classifier approval, native `call` Allow and a managed-policy lock, one
   fresh pinned ORIGINAL upstream server starts with a writable **private
   temporary staging root only**, read-only package/runtime/library mounts,
   namespace isolation, syscall/network restrictions and no inherited secrets.
3. The private server runs original initialize → pinned tools/list →
   original `write_file`. All framing, runtime and stderr are bounded.
   The sandbox owner and descendants must stop/reap before the stage can be
   inspected. A staged file must be the only entry, owner-private, regular,
   exactly as large as the authorized UTF-8 bytes, and SHA-256 identical.
4. The actual original untrusted result is sent to the authenticated native
   result gate. Denial/uncertainty/cancellation/EOF drop the staged output
   **without publication**. After native result Allow, an anonymous `O_TMPFILE`
   is filled from only those verified bytes under the original pinned workspace
   inode. The policy transition lock remains held until the `linkat` no-clobber
   publication finishes; concurrent targets and root replacement fail.
5. On successful durable publication the host receives the **original**
   upstream result. A post-commit sync failure is explicitly reported as
   potentially committed; the system never claims that late cancellation or
   withholding can undo `linkat`.

A valid original JSON-RPC error or `isError` tool result is separately passed
through native result inspection with its original error fields. It carries
no verified output/publication capability; any partial private-stage files
are discarded after owned process cleanup. Malformed responses and failed
containment/cleanup still produce a bounded relay failure, without publication.

## Validation and limits

Linux profile/stage/unit/clippy tests are separate from the accepted read-only
and Git suite. The existing **required Linux original filesystem acceptance**
runs the ignored-in-ordinary-unit `actual_original_write_file_is_confined_to_unpublished_stage`
test using the same pinned installed ORIGINAL server and namespace owner as
SOU-62. A timeout, missing prerequisites, zero tests or a failed assertion
fails that acceptance. Its independent markers show original upstream output
while the *real* workspace and outside marker remain unchanged before release.
The race test rejects replacement of the workspace root after its initial pin.

The required acceptance also installs the actual create-only profile, loads its
full registry through the native daemon, and exercises original-create → read →
verify through the collector and atomic publisher. It checks overwrite,
traversal, extra-field and oversize refusals, spent host IDs, Creating-phase
cancellation, daemon loss before publication and useful read continuation.
The outside sentinel and unrelated workspace entries must remain unchanged;
the independent egress receiver must receive no requests. The final workspace
contains only deliberately committed successful creates.

These controls were independently reviewed on `97db581` (42/42 original
filesystem controls and 15/15 combined real-host controls). They describe that
source's evidence, not a qualification of a later merge candidate. Every new
candidate still needs its own required CI and reviewer acceptance.

Additional required controls now check a late cancellation after commit,
an existing symlink target, and fresh original create/read/verify after a
cancelled call and after daemon restart. A separate writable-stage Node probe
actively attempts TCP and Unix-socket egress against calibrated receivers and
tries runtime/package/outside writes. This tests the writable-stage seccomp
branch, separately from the read-only boundary. The evidence grader requires
these controls; adding them is not a claim they passed on an untested source.

Required controls additionally kill a newly observed ephemeral original worker
and the collector during Creating, and close host input during Creating. Signal
injection requires an independently sampled owned PID/start time and a pidfd;
it never searches for or kills an arbitrary PID/group. Filesystem snapshots,
absent fault targets, owned-process cleanup and fresh successful creates after
worker/collector loss are mandatory. Six deliberately published files are
expected across the complete create scenario. Busy refusals while a cancelled
worker finishes cleanup are bounded and use fresh host IDs; they are excluded
from the three successful write-RPC latency samples.

Linux unit tests also pause the real relay's completion after native result
inspection and after anonymous staging. Cancellation/EOF must discard output;
cancelled IDs remain spent, fresh creates succeed, and managed activation
cannot overtake the held publication boundary. These tests use a task-local
test producer and mock native receipts, with the real Linux publisher. They
are deterministic phase regressions, not original-server acceptance. The
substitution and pause seams do not exist in production builds.

The driver also records three matched-payload unwrapped and protected write
RPC latencies using `monotonic_ns`, their medians and ratio. Initialization and
verification reads are excluded. The protected sample includes native gates,
fresh sandbox/owner startup and durable atomic publication; the unwrapped
sample uses a warm original server. These small observations do not measure
throughput or tail latency. Read the current-source report for actual numbers.

The bounded create profile does not claim arbitrary-server isolation, exhaustive
crash/egress injection, throughput or tail latency. Tests at specific lifecycle
boundaries demonstrate those boundaries only. See the
[requirements/review audit](MCP_FILESYSTEM_CREATE_AUDIT.md) and the
[separate Ask acceptance ledger](evidence/sou-83-ask-acceptance/README.md)
for current-source qualification and historical limits.

### Integration with the current pilot

The create-only profile remains separate from all selected read-only Git
families, including local references, shallow history and ordinary local clones.
The shared read-only registry can select those Git families; a create-only
registry cannot acquire their peer tools. Explicit prepared-pilot budgets are
not supported for this separate create profile and refuse before server startup,
rather than silently leaving an ephemeral writer outside the selected budget.

If the native daemon refuses an original result's size, the collector can spend
the grant with a small correlated error and deliver that error. This replacement
receipt does not authorize publication of the private staged output. The host
ID remains spent and useful read continuation remains available. The Linux
relay regression exercises this boundary through the actual receipt transport
and publisher using a test-only staged producer.

The ephemeral stage has its own pinned workspace identity; the user's original
workspace pin still governs publication. Closed diagnostic output cannot skip
owned cleanup. These integration controls require qualification on the updated
source; historical native reports below do not qualify a later merge.

## Private operator installation (new, opt-in)

Run `python3 scripts/install-sou83-filesystem-create-profile.py --destination /private/new-profile --workspace /private/owned-workspace --node /trusted/node --bwrap /trusted/bwrap` to preview; add `--run` to create a **new** 0700 installation. The script uses the accepted SOU-62 installer and exact pinned ORIGINAL package/runtime/notices, then writes owner-private `profile.json`, `registry.json` and a distinct `policy.yaml`. No existing read-only installation or Agent home is updated. For this opt-in profile, the exact selected original `write_file` is the sole supported side-effecting tool; all other original mutators remain unsupported. The new profile policy removes only the read-only install's general side-effecting deny; it keeps destructive/network/privilege/result-injection denial. Do not share this profile policy with any wider registry.

Binding the installed profile to an authenticated client/native daemon still requires operator review of the new registry/policy hashes and matching source; the installer does not activate any server automatically. Ask continuation requires the separate explicit approval opt-in below.

The pinned ORIGINAL server may create an ordinary `0644` file via its default Node umask. This file remains inaccessible to other users under the private `0700` staging root. After child cleanup, the inspector validates a single matching owner-held regular inode, rejects special/execute bits, and normalizes its permissions to `0600` through the pinned descriptor before comparing its approved content. No untrusted file is released or published before that check.

### Create-specific fault evidence (required for release)

The protected real original-filesystem acceptance now exercises a cancelled post-native-Allow `Phase::Creating` call, an independently stopped native daemon during a second `Phase::Creating` call, and a reused already-spent host ID. Each negative case checks that no target was published and that a healthy same-session or restarted-session read still succeeds. Separately, `native_endpoint` now exercises the actual selected original `write_file` native call/result authority, refuses the second identical result (and a tampered replay), and confirms a new distinct call may proceed. These tests are not a replacement for the standard policy-epoch, egress and Ask qualification. The separate original-create Ask qualification below must also pass.


## Single-use original-create Ask (separate SOU-83 follow-up)

The native approval broker can resume the exact original `write_file` after an
operator inspects and approves one pending call. Enable native approvals in the
new owned daemon home, use an authenticated `--host-session`/`--child-authority`
collector with native liveness, and opt in through the existing
`--native-approval-wait-seconds` flag. See [native approval configuration and
operator commands](NATIVE_ASK_APPROVAL.md). The classifier must positively identify
only `write`; empty, unknown, ambiguous, understated and mixed predictions remain
refused. Native hard Deny cannot be approved. No approval opt-in keeps the normal
correlated Ask refusal.

Pending `selected_invocation.original_create` and `resource_details` contain
`sw-mcp/original-create-resource/1`: canonical workspace path, device/inode,
virtual target, exact UTF-8 byte count and content SHA-256, and
`must_be_absent: true`. The existing signed binding also covers session/epoch,
host ID and raw request hash, registry/schema, snapshot, selected profile,
runtime/package pins and classifier revision. This is observation evidence for
the constrained original-server pipeline, not a `resource_admission` grant for
built-in executors. Ordinary selected Allow calls retain the same typed resource
in their native binding and audit. Resource evidence contains no raw content.
Read-only invocation serialization and grant/key domains are unchanged.

The collector releases its managed-policy lock during the human wait, retains
its exclusive create slot, and starts no ephemeral original writer or staging
operation. After approval it revalidates selected files, root identity, absent
target, classifier, cancellation/deadline and the current native policy before
redeeming once. The broker's TTL, collector wait, existing 30-second call deadline
and owner lease all remain authoritative. It then uses the same fresh private
original server, inspected result and atomic no-clobber publication boundary as
Allow. Rejection, expiry, cancellation, lost owner, daemon restart, drift, root
replacement and a competing target cannot publish. The approval never clears
host taint or authorizes another host ID, target, content or policy epoch.

`verify-sou83-create-approval.py` is required alongside original filesystem/Git
acceptance: three unwrapped calibrations; actual approved create and fresh
create/read continuation; spent-ID refusal; terminal/drift/fault
controls, absent opt-in and hard Deny. It verifies actual file bytes, mode,
link count and whole-workspace snapshots, and requires zero writer starts and
zero private stages before approval or after a refused outcome. Raw syscall
traces remain private because they contain child-authority argv. Signed managed
SQLite/PostgreSQL qualification additionally exercises actual original Allow /
Deny, a new same-policy deployment retiring a pending create, and a fresh exact
Ask after activation. Unit tests alone do not qualify these real-process checks.


The required real-original staging witness also re-runs the unchanged pinned
writer under seven trusted output perturbations **after owned child cleanup**:
extra artifact, wrong bytes, oversized file, external hardlink, symlink, FIFO and
directory. The production output validator must refuse every case with zero
visible publications. A task-local seam exists only in the library test binary;
there is no environment switch or mutation hook in production. The same actual
verified original output is anonymously staged then dropped, challenged by a
competing target, and challenged by root replacement before publication. These
controls test output verification/publication independently from upstream
semantics; they do not claim that the original pinned server itself is malicious.
