# Original-server Ask latency (SOU-124, first slice)

This branch starts from accepted `main` `cdd9d36c65a592455e4f421268758adb6db744b8`.
It adds measurement, not an authority cache. Repeated full-asset verification is
still present. SOU-124 is **not complete** and its performance target remains a
blocker until an equally strict reuse mechanism and native Linux before/after
evidence exist.

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

## Reuse design constraint

The current rehash protects bytes that can change while an approval waits. A
cache keyed only by mtime, inode or an initial successful verification would
weaken that guarantee. Kernel notifications alone do not establish byte
immutability against all writable mappings. No such shortcut is introduced in
this first slice. Reuse must bind verified immutable input identity to the
collector/daemon instance, profile, policy, registry and classifier, and refuse
replacement, permission/owner changes, restarts, overflow or lost observations.

## Current evidence boundary

Development ran on macOS arm64. No native Linux x86_64 runtime, Docker, Podman,
QEMU, Lima, Colima, Multipass or UTM command was available in this session.
Local relay tests and synthetic accounting tests are not Linux performance
evidence. Native baseline/after samples, malicious-replacement acceptance and
the snapshot optimization remain pending. No paid provider, real secret,
private dataset, release or CI-admission change is part of this slice.
