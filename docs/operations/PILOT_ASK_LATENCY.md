# Original-server Ask latency (SOU-124)

This implementation profiles the approved
path and retains per-Ask verified inputs with kernel fs-verity or a bounded local
read lease. Native run `40038036266` on exact source `1137780` completed all
eighty same-runner before/after approvals with zero failed/incomplete samples.
Candidate p95 was 1938.429574 ms for filesystem and 2914.567600 ms for Git, both
within 3000 ms. Full denominators, source identities and historical failures are
retained in `evidence/sou-124/`. A missing or missed target remains an explicit
performance blocker.

## What the measurements mean

The selected-server relay emits content-free `mcp_real_approval_timing` events
with the original host call ID and profile. Stages distinguish full selected
profile/assets verification, policy-boundary acquisition, classifier invocation,
daemon redemption, original request dispatch, original response observation and
result inspection. `stage_ms` and `post_observed_ms` use the collector's monotonic
clock. They start when the collector observes approval, **not** when the operator
decides. They do not measure physical human presence or model effectiveness.
`mcp_asset_verification_timing` separates profile parsing, package-tree hashing,
and pinned runtime/library hashing. Neither event exports paths, arguments,
results, credentials or grants.

The existing exact arguments/content, single-use redemption, expiry, pending
lifetime, cancellation, policy and result-inspection gates remain in place.
No timing changes a deadline or authorizes a call. A failed stage remains failed.

## Collect native Linux samples

Use the installed original Linux filesystem/Git pilot and the existing required
arguments of `scripts/qualify-pilot-ask.py` (see `--help`). Add:

```text
--approval-samples 20
```

This selects a separate performance run with twenty fresh approvals for **each**
profile. It does not resubmit any call. The existing no-dispatch-before-approval,
exact-once redemption, useful original result, independent kernel/wire effects,
peer progress and unrelated-run controls still run for every sample. The default
invocation still selects the original fourteen lifecycle cases. Performance
samples supplement those cases; they do not replace adversarial qualification.

The report retains each case and its original failure. If a run stops early,
`latency` records the missing planned cases as incomplete. A failure or incomplete
denominator prevents `target_met`. A missed target returns nonzero with status
`performance_blocker`, even if the independent security controls passed. p50/p95 use nearest rank over successful
observations and are accompanied by successful, failed and incomplete counts.
If accounting itself fails, cleanup still attempts every active owned host and
the daemon. A failed host cleanup cannot skip the remaining owners; any cleanup
failure keeps the qualification unsuccessful.
The outer metric measures the conservative monotonic duration from immediately
before the operator approval command to the correlated original result.

Retain at least twenty filesystem and twenty Git samples on the **same owned
native Linux machine** before and after the optimization, with exact source,
installed inputs, environment, p50/p95 and failures. The target is p95 <= 3000 ms
for each profile. WSL observations must be identified separately. An absent or
missed target is a performance blocker; never increase timeouts or weaken effect
witnesses to turn it into a pass.

## Conditional immutable-input reuse

One Ask captures its input identities **before** publishing the pending proposal.
The observations are owned by that exact collector/call, never serialized,
shared across daemon instances, or used as a policy/approval result. The profile
is parsed again on resume; its selected path, fields and metadata must match.
A fresh policy boundary, classifier assessment, native instance/registry binding,
expiry/cancellation check and single-use broker redemption remain mandatory.
Classifier setup/semantics are unchanged.

For each regular file, the initial SHA-256 verification, metadata and optional
kernel proof concern the same opened file description. On native Linux x86_64,
an already enabled `FS_IOC_MEASURE_VERITY` proof binds the verified content SHA
to a separate kernel digest. No filesystem option or asset is changed.

Ordinary installed files of at least 64 KiB may instead retain a read lease on
that same description, through a private CLOEXEC descriptor and a dedicated
thread-directed, blocked SIGIO receiver. Only ext4, XFS, btrfs and tmpfs are
eligible. Remote, FUSE, layered and unknown filesystems always rehash. Acquisition
failure, writable mappings, foreign ownership or the 256-proof per-Ask cap falls back to
full hashing. An established proof is never reacquired. Pending/forced breaks,
worker loss and unlocks invalidate it permanently; the worker marks it invalid
before releasing a blocked writer. A cancelled write-open cannot heal a proof.
Fresh path/descriptor identities and retained leases are checked again after
verification. This preserves the existing validation boundary; it does not claim
an atomic snapshot of the entire tree through later execution.
The collector process additionally caps all its concurrent retained leases at
512 descriptors; exhaustion falls back to hashing. A slot is returned only when
the private descriptor closes, without recycling any Ask's previous proof.
Directory descent retains its before/after observations without duplicating
them in the caller. A resume remeasures every captured verity proof; files with
no captured verity proof use their retained lease or full byte hashing directly.

See the [kernel fs-verity contract](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
and [Linux lease contract](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html).

Every package entry is still traversed, bounded and checked, including directory
identities and symlink targets. Added, removed, replaced or changed entries
refuse. For files without an eligible kernel proof, bytes are read and hashed again even
when metadata matches. Neither mtime, notifications nor a read-only bind mount is
accepted as a byte-immutability proof. `mcp_verified_inputs_resume` reports the
numbers of fs-verity files, retained lease files and files rehashed, without paths or
content. An all-fallback run is **not** evidence of an optimized accepted path.

Unit controls were added for same-length writes, matching-metadata writes,
replacement, permission/symlink changes, package structure changes and lost
proof. The Linux read-lease controls include pending breaks, writer cancellation,
writable mappings, independent owners, disposal, CLOEXEC and bounded capacity.
The ignored `native_read_lease_fast_path_qualification_requires_real_proofs`
control requires a real unprivileged local filesystem fixture and refuses a
fallback-only result. The separate ignored
`native_verity_reuse_requires_a_real_immutable_inode` control requires an explicit
operator-owned `SOU124_VERITY_FIXTURE` which already has fs-verity enabled; it
never enables it. That isolated control also cannot replace original-server,
malicious replacement/restart/expiry, concurrent-peer and latency qualification.

## Same-host before/after qualification

The optional manual `mcp-real-filesystem.yml` input
`ask_latency_baseline_sha=8c275fcc9abdee99d4997cd4a985e6ce14d751e6`, together with
`native_preparation_only=true`, uses the existing native Ubuntu job. It does not
add a matrix or change admission. The baseline predates verified-input reuse.
Both exact-source binaries have source-build receipts and share pinned runtime
assets and one current measurement harness on the same runner. Harness source
and each runtime implementation source are attributed separately. Hash-locked
npm/Python/wheel inputs are prepared before the external-network-denied
measurement; profile installation during measurement is explicitly offline. The strict kernel read-lease witness must pass first.

`scripts/qualify-pilot-ask-comparison.py` runs twenty filesystem and twenty Git
samples on each side and independently validates full denominators, effects,
source/build identity, peer progress, actual collector reuse and percentiles.
A slow but complete baseline is retained. A candidate missing p95 <= 3000 ms for
either profile exits nonzero. Only bounded JSON reports and the kernel control
summary are exported; raw provider/authority traces remain private.

Local macOS checks include 1696 Rust tests passed, 13 ignored; strict workspace
all-target clippy and formatting; 1220 Python tests run, 79 platform/optional
skips and no failures. These checks are not native performance evidence. Current
native measurements and any failed attempts are retained separately in
`evidence/sou-124/`. No paid provider, real secret, private dataset, release or
CI-admission change is part of this implementation.

### Native follow-up

Linux canonical identity uses an `O_PATH` descriptor and its kernel
`/proc/self/fd` path after checking the complete retained metadata against that
descriptor. This avoids repeated userspace ancestor traversal. Symlinks retain
resolved-target canonical checks; unavailable proc paths use normal canonical
resolution. Neither a pathname label nor matching metadata authorizes SHA reuse.

The paired measurement first runs a two-profile correctness preflight using the
same exact candidate and all existing approval/effect/peer controls. Its report
is explicitly outside performance acceptance and cannot replace the required
20 filesystem plus 20 Git samples per side. Failure captures finite codes and
bounded stage timings, never raw tool arguments, credentials or host output.
All failed native attempts and their baseline measurements remain retained
alongside the passing current comparison; failed rows are never omitted or
reclassified as successful samples.

Only the explicitly requested manual paired benchmark has a 140-minute outer
runner budget: two existing 3600-second measurement-side budgets plus bounded
setup/preflight. The complete baseline alone took approximately 49 minutes in
the retained attempt. Ordinary PR/native jobs retain 65 minutes. Host, approval,
call and per-case deadlines are unchanged; a slow sample still misses 3000 ms.

For regular Linux package-tree leaves, verification uses the existing opened
read descriptor for canonical identity and hashes/proofs. It compares the walk's
lstat identity before the read and a fresh lstat plus descriptor identity afterward.
The walker retains canonical identity and before/after validation for every
ancestor directory and symlink. This avoids repeated O_PATH opens of the same
regular leaf without treating metadata as content authority. Files without a
valid retained kernel proof are still hashed; standalone runtime/library paths
keep the full independent path checks.

The common before/after harness requests `strace --seccomp-bpf` with the exact
same exec/open/write/clone/exit witness set. This avoids ptrace stops for syscalls
which the trace was already discarding, without removing any observed original
server effect, wire write or thread-lineage event. Strace may fall back to its
ordinary tracer if kernel filtering is unavailable; the report records the
requested mode, not an unproven successful filter installation. All existing
deadlines and positive/negative effect assertions still apply. Both paired sides
must use this same current harness; earlier ordinary-ptrace runs stay separately
attributed and cannot be spliced into the new comparison.

Fs-verity reuse is restricted to kernel implementations on ext4/f2fs/btrfs.
FUSE forwards this ioctl to its userspace server, so an apparently successful
measurement on FUSE, remote, layered or unknown storage cannot authorize reuse;
those paths hash bytes instead. The filesystem type is read from the actual FD.
See the [kernel FUSE implementation](https://github.com/torvalds/linux/blob/v6.17/fs/fuse/ioctl.c)
and [strace internals](https://github.com/strace/strace/blob/master/doc/INTERNALS.md).
