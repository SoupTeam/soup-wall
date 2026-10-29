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

`scripts/qualify-edit-review.py` is inert by default. Its explicit `--run` mode
uses the genuine pinned installed host with an owned local scripted model, no
paid inference, independent preservation witnesses and a fixed control inventory.
The focused `linux-installed-edit` workflow retains its finite `review/report.json`
beside exact source and binary identities. Failed attempts remain separate.
