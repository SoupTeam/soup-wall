# Original-server Ask latency (SOU-124, development)

This implementation uses accepted `main` `6fdbc56`. It profiles the approved
path and retains per-Ask verified inputs with kernel fs-verity or a bounded local
read lease. macOS development checks pass; native before/after qualification is
required before claiming the p95 target. A missing or missed target stays an
explicit performance blocker.

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
failure, writable mappings, foreign ownership or the 96-proof cap falls back to
full hashing. An established proof is never reacquired. Pending/forced breaks,
worker loss and unlocks invalidate it permanently; the worker marks it invalid
before releasing a blocked writer. A cancelled write-open cannot heal a proof.
Fresh path/descriptor identities and retained leases are checked again after
verification. This preserves the existing validation boundary; it does not claim
an atomic snapshot of the entire tree through later execution.

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

Local macOS checks include 1694 Rust tests passed, 13 ignored; strict workspace
all-target clippy and formatting; 1173 Python tests run, 64 platform/optional
skips and no failures. These checks are not native performance evidence. Current
native measurements and any failed attempts are retained separately in
`evidence/sou-124/`. No paid provider, real secret, private dataset, release or
CI-admission change is part of this implementation.
