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

## Read a bounded unified diff

Select each completed-run output explicitly with `--diff`. Separately select
and consent to any baseline copies. A baseline must match the immutable plan's
recorded pre-edit size and SHA-256 for that replacement target:

```sh
agentfw edit-session review --run "$EDIT_RUN" --sha256 "$EDIT_PROFILE_SHA256" \
  --diff result.txt --diff created-1.txt \
  --diff-baseline "result.txt=$BASELINE_COPY" \
  --consent-private-content --consent-baseline-content
```

Without a baseline, the selected output is labelled
`new_file_view_no_baseline_selected`, including replacement outputs. This is a
view from an empty comparison side; it does not invent an unchanged file or a
trusted origin. Explicit copies establish recorded content identity, never old
inode or writer provenance. An absent output refuses rather than becoming an
invented empty file. Baselines must be owner-private mode-0600 regular files
with one link, matching user/group and no unsupported xattrs, outside the run,
output root and component home. Exact canonical baseline paths can contain
spaces/Unicode, including the leaf; existing declared-output name rules remain.

Diff mode is read-only and conflicts with export, full-file display and the
older `--baseline` comparison mode. It uses no Git, shell, pager, diff executable,
provider or MCP tool. Default review and sanitized support bundles remain
content-free. Diff text is not automatically saved or included in an archive.
Application/export permissions and formats stay unchanged.

The `sw-installed-edit-diff/1` response includes a content-free per-file summary
and a consented `display` array of unified text. Text and basename labels use
Rust ASCII escapes; synthetic header/hunk/line delimiters are the only literal
line breaks. CRLF preserves escaped `\r`; missing final LF has a deterministic
`No newline at end of file` marker. Full-file hunk ranges count LF-delimited
source lines from one, with start zero for an empty side. Binary NUL, invalid
UTF-8, oversized and unsupported inputs explicitly refuse the entire display.
An unchanged verified pair has headers and zero changes; an empty new-file view
still explicitly lacks a baseline.

Bounds per invocation:

| Resource | Limit |
| --- | --- |
| Exact outputs / baselines | 8 / 8 |
| Bytes per selected file | 4096 |
| Combined comparison input | 64 KiB |
| Aggregate LCS table cells | 1,048,576; at most 2 MiB table storage |
| Aggregate escaped unified display | 32 KiB |
| Complete JSON response | 128 KiB |
| Existing shared read/recheck budget | 2 MiB / cooperative 10 seconds |

Repeated identical inputs use an equality fast path. Other comparisons charge
the common algorithmic budget; a large repeated-line edit may explicitly exceed
it. No input, line, file or hunk is silently omitted or truncated to fit a cap.
Any refusal returns nonzero and an explicit content-free `incomplete` outcome
with an empty display, never a partial clean preview or private path in an error.

`observation_sha256` retains the existing run/output observation contract.
`comparison_sha256` additionally binds the diff format, actual baseline bytes,
descriptor and parent identities, hashed canonical paths, summary and rendered
display. Baseline and output identities are rechecked before returning, including
output rechecks after the last baseline. A changed/substituted file or parent
refuses. These finite observations do not freeze future same-user writes; the
accepted private sole-writer assumption still applies. Neither digest grants
execution, application, export, rollback or cleanup permission.

## Save a private bundle

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

## Qualification

`scripts/qualify-edit-diff.py` is inert by default. Explicit `--run` performs a
fixed 42-control installed qualification outside checkout, with genuine pinned
Claude and an owned local scripted provider. It covers actual mixed two/eight
file runs, dense-line inputs, benign/unsupported outcomes, separate consent,
scope and file-type refusals, baseline/output/parent races and sibling preservation.
A separately exercised test-only preload observer records attempted external
process execution; every diff call must observe zero such attempts and zero
provider requests. Controlled race mutations are labelled separately from product
behavior. No paid inference or private evaluation data is used.

The targeted installed-edit workflow retains finite `diff/report.json`, failed
attempts, per-file preservation witnesses and exact source/component/Agent/host
identities. The complete console summary also binds the report digest. Native
execution is Linux x86_64 only; macOS/Windows remain unsupported for this command.
Shared final Ready qualification, CodeQL, candidate admission and merge remain
with the TL; this focused workflow does not replace them.

`scripts/qualify-edit-review.py` is inert by default. Its explicit `--run` mode
uses the genuine pinned installed host with an owned local scripted model, no
paid inference, independent preservation witnesses and a fixed control inventory.
The focused `linux-installed-edit` workflow retains its finite `review/report.json`
beside exact source and binary identities. Failed attempts remain separate.
