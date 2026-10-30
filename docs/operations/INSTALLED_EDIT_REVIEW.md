# Review and privately save installed edit outputs

On native Linux x86_64, `agentfw edit-session review` inspects the exact mutation
outputs declared by one completed installed edit run. Use the run path and
profile SHA-256 recorded when you prepared and ran it:

```sh
agentfw edit-session review --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256"
```

The compact JSON response includes each exact name, existence/type, byte count,
SHA-256, metadata identity and an `observation_sha256`. The default contains no
file content. It never searches directories, invokes a host/tool/provider,
decides Ask requests or creates execution authority. Files and retained records
stay unchanged. The original project is never an application destination.

Only a consistent immutable profile, completed terminal record, matching local
owner cleanup/revocation receipt and inactive recorded processes on the current
boot permit review. Active, interrupted/cancelled, stale, foreign, contradictory
or unsupported state refuses. A missing PID alone is insufficient. These local
records and current digests do not attest who wrote a file, successful mutation,
host delivery or model consumption. Review reports current bytes, which may have
been independently changed after the run.

To see one file, consent explicitly. Text is rendered as Rust ASCII escapes,
including newlines, ESC, Unicode and bidi controls; treat it as untrusted data:

```sh
agentfw edit-session review --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256" \
  --show result.txt --consent-private-content
```

Replacement plans retain a content digest and metadata, not old content. Without
an explicit baseline, the response says `baseline_unavailable`. If you retained
an owner-private regular copy independently, select it explicitly:

```sh
agentfw edit-session review --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256" \
  --baseline "result.txt=$EDIT_BASELINE" --consent-private-content
```

The bounded comparison displays escaped before/current text only after the
copy's byte count and SHA-256 match the recorded pre-edit content identity.
It does not claim that the copy has the original inode or prove its provenance.
Missing/mismatched copies refuse; no history is reconstructed from logs or model
text. Binary content has a summary but cannot be displayed or compared as text.

To save a private bundle, take `observation_sha256` from a fresh summary and name
each file individually. Choose a new directory under an existing owner-only
parent outside the output root, run and installed component:

```sh
agentfw edit-session review --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256" \
  --export "$EDIT_NEW_BUNDLE" --include result.txt \
  --expect-observation "$EDIT_OBSERVATION_SHA256" --consent-private-content
```

This is a **private content bundle**, separate from the unchanged sanitized
`edit-session status --support-bundle` operation. It contains only consented
output leaves plus a finite `sw-installed-edit-private-review-bundle/1` manifest.
The manifest records the observation, exact bytes/hashes and private-content
label; it contains no provider configuration, prompts, logs, grants or tokens.
Binary bytes may be exported with explicit consent. `manifest.json` is reserved.

Bounds are eight declared direct-child outputs, 4096 bytes per file, 32 KiB for
the manifest, 128 KiB for the response and a shared 2 MiB/10-second read budget.
Links, hard links, FIFOs/devices, unsupported ownership/modes/xattrs, redirected
parents and oversized files refuse. Descriptor-pinned reads detect identity or
content changes. An advisory directory lock conflicts with accepted writers;
the existing sole-writer assumption still excludes uncontrolled same-UID writes.
Selected records and outputs are rechecked before publication. No finite
observation predicts writes after that observation.

Publication reuses the support export's create-new directory primitive: private
staging, 0700 directory, 0600 files, no-overwrite atomic rename and cleanup on
prepublication failure. A stale observation refuses even if the bytes match but
metadata changed. Existing destinations are preserved; retry with a fresh
observation and a new destination only after inspecting the result independently.
An OS error after rename can leave a complete published bundle; inspect it rather
than overwrite or automatically retry. Process termination may retain private
staging. No run deletion, pruning, rollback or automatic application is provided.

## Confirm and export a complete selected set

On native Linux x86_64, select two to eight declared mutation outputs from one
completed run. Existing 4096-byte file limits apply. First preview the entire
selected set and exact new destination:

```sh
agentfw edit-session export-set --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256" \
  --include first.txt --include second.txt --out "$PRIVATE_EXPORT_PARENT/new-set" \
  --consent-private-content
```

Private-content consent is required even for this preview. Text is displayed
using the existing escaped untrusted-text rendering; binary content has a
size/hash summary. Preview creates no stage or destination. Review every file
and the destination, then use the exact `confirmation_sha256`:

```sh
agentfw edit-session export-set --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256" \
  --include first.txt --include second.txt --out "$PRIVATE_EXPORT_PARENT/new-set" \
  --consent-private-content --apply --confirm "$EDIT_EXPORT_CONFIRMATION_SHA256"
```

The confirmation binds the selected names, per-file descriptor identities,
hashes and sizes, retained run/profile/terminal/cleanup observation, and exact
canonical destination plus parent identity. Choose a new absolute path with an
existing owner-private parent, no aliases/symlink ancestors and no overlap with
the run, output root or Agent component home. Changed selection, source state,
files or destination require a fresh preview. Duplicate, undeclared, absent,
linked, hardlinked, special and oversized files refuse the whole set. Active or
incomplete runs refuse too. No checkout or inventory prerequisite is needed.

The shared private exporter stages at most eight regular files and one manifest
on the destination filesystem (nine files / 144 KiB total primitive bound).
Directory mode is 0700; file modes are 0600. Final source, destination and stage
checks precede atomic no-replace publication. The versioned
`sw-installed-edit-private-result-set/1` manifest contains the confirmation,
run/profile digests and selected per-file identities/hashes/sizes. It excludes
prompts, tokens, raw receipts, authority, unselected output observations and
unrelated retained files. Original outputs, immutable plans and pre-existing
destinations are preserved. No provider or tool is invoked. Export does not
upload content or grant authority. This local copy does not attest its writer.

Read, copy, validation, cancellation and publication failures return nonzero
with an explicit `incomplete` response. Cleanup unlinks only exact created
regular inodes after independently checking their identities, then attempts
empty-directory removal through the pinned parent. Changed/unavailable stages,
substituted files and injected entries remain for inspection; cleanup never
recursively deletes a destination. SIGINT/SIGTERM cancellation is cooperative
before publication. A signal racing commit or a parent-sync error can leave a
complete destination despite an incomplete response. Inspect the exact result
before retrying; forced termination can retain a hidden `.agentfw-doctor-*`
stage. A confirmation does not authorize rollback, pruning or manual cleanup.

## Qualification

`scripts/qualify-edit-export-set.py` is inert by default. Explicit `--run` uses
the genuine installed host and owned local scripted provider for two- and
eight-file create/replacement runs, exact manifests/bytes, refusal boundaries,
last-file and destination races, copy/publication I/O faults, cancellation and
stage/parent substitution. All 31 controls must be attempted and pass with zero
provider requests during export and independent preservation witnesses.
The focused workflow retains `export-set/report.json` and exact source,
component, binary, genuine-host and report digests, including failed attempts.

`scripts/qualify-edit-review.py` is inert by default. Its explicit `--run` mode
uses the genuine pinned installed host with an owned local scripted model, no
paid inference, independent preservation witnesses and a fixed control inventory.
The focused `linux-installed-edit` workflow retains its finite `review/report.json`
beside exact source and binary identities. Failed attempts remain separate.
