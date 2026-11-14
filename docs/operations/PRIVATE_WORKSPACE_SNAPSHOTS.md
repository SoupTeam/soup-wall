# Private workspace snapshots

An explicitly captured snapshot is a private view of earlier project bytes. It
is never the current live workspace. This independent capability reuses the
accepted original single-root filesystem profile, installed preparation and
launcher. It does not depend on the optional multi-root file-link profile.

## Preview and consent

Use native Ubuntu 24.04 x86-64 as a non-root operator. Choose one canonical owned
source and a **new** destination in an owned private `0700` parent outside it.
Installation/component state, named sibling project roots and explicitly supplied
protected roots cannot overlap the destination. Installation/session state is
not a supported source. Other unregistered project locations must be supplied as
`--protected-root` exclusions; no ambient project discovery is performed.

```sh
agentfw pilot --home /private/agent-home snapshot preview \
  --source /owned/project --destination /private/snapshots/review-1 \
  --protected-root /owned/other-project
agentfw pilot --home /private/agent-home snapshot create \
  --source /owned/project --destination /private/snapshots/review-1 \
  --protected-root /owned/other-project --confirm EXACT_PREVIEW_CONFIRMATION
agentfw pilot --home /private/agent-home snapshot inspect \
  --snapshot /private/snapshots/review-1
```

Preview observes metadata, counts and byte limits without reading/copying file
contents or creating a destination. Confirmation binds the exact source and
parent identities, scope metadata, destination, exclusions and limits. Any
changed scope requires a fresh preview. Capture reads retained no-follow file
descriptors, watches source mutation and rechecks retained/named objects and
ancestors. It executes no project commands, hooks, Git helpers or models.

The first slice accepts owned regular files/directories on local ext4, XFS,
Btrfs or tmpfs. Limits are 128 files, 128 directories including the root, 256
entries including the root, depth 32, 8 MiB per file and 32 MiB total, plus a
16 MiB free-space reserve. Links, hardlinks, special files, nested/unsupported
mounts, shared-writable objects, installation/session store names and recognized
credential material refuse. The capture reads only explicitly consented project
content; it never adds provider environment, session state, grants or approvals.
The name/material refusals are conservative scope guards, not a general secret
classification guarantee for arbitrary operator-supplied text.

Files are private from creation. A complete generation contains a source-identity
receipt, per-file hashes, content-tree hash, completion marker and a stable
lifetime lease. Files/directories become `0400`/`0500`; the generation stays
`0700`. Publication syncs the full generation and uses Linux exclusive rename.
Failure or interruption cannot publish a selectable partial generation, and a
concurrent winner is never overwritten/deleted. A process killed before cleanup
may leave an unselectable `.snapshot-*` staging directory.

## Recover an interrupted capture

Use the private directory that contained the intended snapshot destination as
the store. Review the reported stage and use the confirmation from its preview.

```sh
agentfw pilot snapshot recovery-inventory --store "$store"
agentfw pilot snapshot recovery-preview --store "$store" --stage "$stage"
agentfw pilot snapshot recovery-apply --store "$store" --stage "$stage" --confirm "$confirmation"
```

Only an abandoned stage with a verified owner record is eligible. Active
captures and unknown stages, including older stages without an owner record,
stay in place. Keep uncertain stages for manual review. If recovery stops
after recording consent, repeat the same apply command with the same token.
Keep the private recovery journal for retry. Recovery never publishes a
snapshot or modifies the original workspace.

## Explicit installed selection

Use the existing preparation command with all normally required pinned inputs.
The filesystem workspace must be the selected generation's `workspace` child;
the existing Git workspace remains an independently selected ordinary repository:

```sh
agentfw pilot --home /private/agent-home preview --prefix /private/pilot \
  --filesystem-workspace /private/snapshots/review-1/workspace \
  --git-workspace /owned/git-project \
  --workspace-snapshot /private/snapshots/review-1
# Repeat the same explicit inputs with prepare --apply, then run normally.
agentfw pilot --home /private/agent-home status --prefix /private/pilot
```

Capture never activates a snapshot. Preparation verifies completeness and hashes,
records a fresh workspace identity and uses fresh runtime authority. Other Git
profile extensions and multi-root selections are unsupported combinations.
Original tool names, schemas, argument bytes, Ask floors and result inspection
remain unchanged. The native sandbox verifies the receipt and files, copies
matching bytes into kernel-sealed images and mounts those immutable images
read-only under `/workspace`. The same verified bytes supply execution. A later
host-file replacement cannot redirect a mount or change a running image.

Inspection/status identify the captured source identity and content-tree hash.
The current-source observation is explicitly metadata-only: changed,
unavailable/unsupported, or matching recorded metadata. It is never proof that
the source is still the captured content. Owner-modified generations refuse
fresh selection if their identity, permissions, completeness or hashes change.
An already running view stays on its sealed earlier bytes.

Refresh means a new preview/create into a new destination. It never modifies an
existing generation or automatically changes an active/prepared selection.

## Removal and failure controls

```sh
agentfw pilot --home /private/agent-home snapshot remove \
  --snapshot /private/snapshots/review-1 --confirm EXACT_REMOVAL_CONFIRMATION
```

Take removal confirmation from a fresh inspect. Removal takes the exclusive side
of the same stable lease held across run admission, host lifetime and cleanup.
An in-use snapshot refuses without stopping its run. After exclusive withdrawal,
only that private generation is removed using descriptor-anchored operations.
Source and sibling project data are never changed. An idle prepared selection
that refers to a removed generation becomes stale and must be selected again.

Focused development acceptance uses `mcp-real-filesystem.yml` with
`installed_focus=workspace-snapshot`, `native_preparation_only=true`, other flags
false and stability off. It exercises installed CLI capture, real original-server
reads after source edits, active-run removal refusal, fresh generations and
explicit removal outside checkout. Bounded low-space, source-copy mutation,
replacement and publication-collision controls run the same installed library
with owned fault injection, without filling runner storage. Native tests verify
that the exact execution descriptors are kernel-sealed and retain earlier bytes
after host-file tampering. Failed/incomplete outcomes are retained. Shared Ready
qualification and merge remain TL-owned.
