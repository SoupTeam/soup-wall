# Runtime admission handoff

This is the author preparation procedure for an exact private Linux runtime.
It does not grant native clearance, kit handoff, pilot readiness or publication.
Use the accepted [installed inventory contract](installed-runtime-inventory.md)
and [material conditions](private-runtime-clearance.md) without changing their
refusal rules. Earlier reports retain their actual source and selected bytes.

## Upstream hold checked on 8 November 2026

The selected Node 22.23.4 predates the
[announced November security release](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases).
Upstream schedules HIGH-severity fixes for the 22.x, 24.x and 26.x lines on or
shortly after 11 November. Its announcement does not disclose affected code or
a patched version. Keep this finding unresolved; neither another affected
release line nor a package-license decision establishes non-applicability.

Until upstream publishes the fix, the useful deliverable is a reproducible
blocked candidate, its raw scans, copied compliance material and explicit review
worklist. Do not create `status: reviewed` / empty native findings to make it
pass. No timer or release date is evidence that a fix has actually shipped.

## Author evidence package

Prepare a new private selection from one clean, full source commit. Record the
actual platform, compiler, selected executable hashes and complete system ELF
closure. WSL2 evidence must remain labelled WSL2. Use a short owned temporary
directory for Unix sockets; shortening its path must not alter product limits.

Run the existing installed-pilot qualification with the owned scripted provider
and preserve useful reads, refusals, benign workflows, cleanup and failed
attempts. This does not measure live-model effectiveness. Do not start a
duplicate all-platform CI matrix for this author handoff.

Fetch the official RustSec database explicitly, record its exact clean commit
and the actual upstream check time, and run bounded scans. The validators bind
digests and nonfuture timestamps; they do not certify online freshness or impose
a maximum age. An old but matching report is not a current upstream review.

From the clean checkout, with existing absolute private inputs:

```bash
python3 -B scripts/generate_inventory.py \
  --selection "$SELECTION" --expected-commit "$REVIEWED_SOURCE" \
  --rustsec-db "$RUSTSEC_DB" --rustsec-commit "$RUSTSEC_COMMIT" \
  --output "$EVIDENCE_ROOT/inventory-raw.json"

python3 -B scripts/build-runtime-compliance.py \
  --selection "$SELECTION" --expected-commit "$REVIEWED_SOURCE" \
  --inventory "$EVIDENCE_ROOT/inventory-raw.json" \
  --output "$EVIDENCE_ROOT/compliance"
```

Both output locations must be new. Expected unresolved findings make the raw
inventory exit nonzero. Preserve that exit and its complete scanner results;
failure of a native version probe must not suppress the package scans. The
copier re-verifies installed notices, covered source and the lock identities.
Its proposal includes pending licenses and every observed supported advisory
record. `UNREVIEWED`, empty authority, evidence references and rationale are
intentional author-side output and cannot pass unchanged.

Supply the reviewer with the selection and its referenced installed material,
raw inventory and generated Python scan input, exact RustSec identity, complete
compliance directory, qualification reports and their hashes. Also retain:

- The official Node announcement and check time, with no invented CVE or fix.
- Selected Git, bubblewrap, Node, host Python and Git-profile Python identities.
- Every selected executable's system libraries and exact source/notice material.
- Earlier exact-material decisions as historical references; do not transfer
  their authority to a new source, selection or changed material.
- A separate list of unavailable platform checks and unresolved native source,
  redistribution or advisory assertions.

## Reviewer and final admission

The responsible maintainer reviews the actual copied material and completes
the exact package/license conditions and advisory evidence. Bind every scanner,
package, source, ID, alias and full record digest. Supported maintenance or
absent-code decisions do not discharge another vulnerability or native finding.

The native review must independently cover all five selected interpreters/tools
and the exact system-library union required by `--native-reviews`. Corresponding
source and distribution obligations remain separate from package decisions.
If any component still has findings, preserve the nonzero inventory and hold.

After all blockers have a supported resolution, rerun the CLI with the reviewed
native input and completed material proposal into another new output filename.
Recheck source, selected trees, scan inputs and all supplied compliance files.
The TL then performs the independent current-source/native acceptance and the
normal exact-candidate CI/admission steps. Only their successful scope can be
accepted; merging preparation tooling does not authorize a runtime handoff.

## When the patched Node release exists

Verify the official release, archive checksum, actual executable, notices and
advisory ranges before choosing a new pin. Refresh the authoritative installer
and preparation archive/executable pins, upstream identity and Node license,
inventory native source pin, scope descriptors and candidate packaging inputs.
Regenerate the original filesystem closure against the exact locked package
archive paths; preserve file-set, link, metadata and execution argument limits.
Refresh any affected scope/index or release-document hashes through the existing
tools, retaining their explicit member sets and historical evidence.

Rebuild the selected binaries, prepare a new generation, regenerate complete
inventory/compliance material and rerun compatibility/useful/refused controls.
A changed review JSON or a newer version label cannot qualify old selected
bytes. Keep the pre-fix candidate and its unsuccessful observations as history.

## Recorded author checkpoint

The [8 November preparation record](evidence/private-candidate/runtime-admission-preparation.json)
binds the executed source `9d08dc74`, selection, raw inventory and private review
archive. Its explicit-policy WSL2 run passes all twelve cases and both benign
workflows. It is not a native Ubuntu or live-model acceptance claim.

The initial invocation selected `linux-readonly-v1/policy.yaml` with the
qualification command's different default shared-source Ask expectation and
passed ten cases. That preset does not implement the expected Ask-on-any-derived-
read contract. The corrected invocation selects the previously used explicit
policy with SHA-256
`dba24a1b419040d5f5dad62dfd485db6637c9359f37b9642f458101793062dbc`.
No policy, expected-rule assertion, witness or limit was changed to obtain its
result. These are separate policy scopes; the first result remains unsuccessful.

The review archive contains 595 copied package compliance/source files, the
complete unreviewed package/advisory proposal, actual selected-binary facts,
copyright material for all thirteen selected system-library paths, forty
retained upstream notice files and the original findings/results. The loader's
dpkg diversion is correlated through its verified canonical same-file path;
it is not omitted from coverage. It contains review material, not an executable
runtime installer or a qualified kit.

The raw CLI remains nonzero, and the generated proposal is independently
rejected as `runtime_reviews:decision_invalid`. Prior maintainer decisions need
renewal against this exact source/selection/material. The direct Ubuntu CVE API
query timed out; observed package versions and retained copyright do not replace
that missing comprehensive native advisory review. The official package pages
for [glibc](https://packages.ubuntu.com/noble/libc6),
[Expat](https://packages.ubuntu.com/noble/libexpat1) and
[libcap2](https://packages.ubuntu.com/noble-updates/libcap2) match the installed
versions observed at this checkpoint; this comparison grants no clean native
or distribution assertion.
