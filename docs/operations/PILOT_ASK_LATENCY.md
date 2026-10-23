# Original-server Ask latency (SOU-124, development)

This branch starts from accepted `main` `cdd9d36c65a592455e4f421268758adb6db744b8`.
It adds stage measurements and a conditional, in-memory immutable-input reuse
path. SOU-124 is **not complete**: local workspace checks and clippy have passed
on macOS arm64 (1661 passed in Rust workspace), but accepted installed assets have not
been shown to support that path on Linux x86_64, and native before/after samples are
absent. The performance target remains a blocker.

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

For each regular file, initial SHA-256 verification, metadata and the optional
kernel measurement concern the **same opened descriptor**. On native Linux x86_64,
only an already enabled `FS_IOC_MEASURE_VERITY` proof allows reusing that file's
verified content SHA. The kernel digest is not the profile's ordinary SHA-256;
the initial full read binds the two. A fresh opened descriptor must still match
the original inode/device, owner, group, mode, link count, size, timestamps and
measured proof. Missing, changed or failed proof refuses the continuation.
The code never enables verity, installs assets or changes filesystem options.
See the [kernel fs-verity contract](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html).

Every package entry is still traversed, bounded and checked, including directory
identities and symlink targets. Added, removed, replaced or changed entries
refuse. For ordinary mutable files, bytes are read and hashed again even when
metadata matches. Neither mtime, notifications nor a read-only bind mount is
accepted as a byte-immutability proof. `mcp_verified_inputs_resume` reports the
number of immutable files reused and mutable files rehashed, without paths or
content. An all-fallback run is **not** evidence of an optimized accepted path.

Unit controls were added for same-length writes, matching-metadata writes,
replacement, permission/symlink changes, package structure changes and lost
proof. They have not run on this source. The ignored
`native_verity_reuse_requires_a_real_immutable_inode` control requires an explicit
operator-owned `SOU124_VERITY_FIXTURE` which already has fs-verity enabled; it
never enables it. That isolated control also cannot replace original-server,
malicious replacement/restart/expiry, concurrent-peer and latency qualification.

## Current evidence boundary

Development ran on macOS arm64. No native Linux x86_64 runtime, Docker, Podman,
QEMU, Lima, Colima, Multipass or UTM command was available in this session.
Local relay tests and synthetic accounting tests are not Linux performance
evidence. Native baseline/after samples, malicious-replacement acceptance and
qualification of the conditional reuse path remain pending. No paid provider, real secret,
private dataset, release or CI-admission change is part of this slice.
