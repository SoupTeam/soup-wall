# Remove owned Linux pilot assets

`scripts/pilot-cleanup.py` inspects one explicitly named generation under a
private preparation prefix. It supports the accepted SOU-111 runtime selections
and SOU-115 native prerequisite receipts. Use an ordinary Linux account with
read access to the process records needed to prove the generation is unused.
This command starts no processes and executes no selected binaries.

## Plan first

Supply the exact absolute canonical prefix and a 32-character hexadecimal
generation directory name. Do not supply a home directory or a wildcard.

```bash
umask 077
python3 -B /absolute/soup-wall/scripts/pilot-cleanup.py \
  --prefix /absolute/private-pilot-preparation \
  --generation GENERATION_ID
```

The JSON result classifies the generation:

| Classification | Behavior |
| --- | --- |
| `current` | Retains the currently selected generation; no removal confirmation. |
| `inactive` | Receipt and complete inventory verified, no active use observed; emits a confirmation hash. |
| `active-or-uncertain` | Process references or unreadable process records prevent removal; no processes are stopped. |
| `incomplete` | Known preparation layout without a completed receipt; contents remain for diagnosis. |
| `unrecognized` | Unknown layout without a supported receipt; contents remain untouched. |
| `refused` | Invalid input, tampered receipt, unexpected layout, link, ownership or mount condition; no removal is authorized. |

A plan binds confirmation to the prefix, generation inode, receipt, selection
marker and complete file inventory. It does not change modes or write files.
Preparation receipts are local ownership records, not publisher signatures.

## Remove one inactive generation

Read the plan and copy its exact `confirmation` into the explicit removal:

```bash
python3 -B /absolute/soup-wall/scripts/pilot-cleanup.py \
  --prefix /absolute/private-pilot-preparation \
  --generation GENERATION_ID --remove --confirm CONFIRMATION_SHA256
```

Keep the bounded JSON result privately. The command revalidates the receipt,
inventory, selection marker and process use immediately before deletion.
Changed inputs require a new plan. Current, active and uncertain generations
cannot be force-removed. Switch to another verified generation through the
accepted preparation interface before considering the previous one for cleanup.

Native prerequisite removal deletes only that inactive build generation.
Runtime asset pruning preserves `filesystem-workspace` and `git-workspace`
in place, including their files and Git metadata. Its result is
`assets-removed-workspaces-retained`; the generation directory remains as their
container. Its now absent selection is not runnable. A later plan treats that
residual directory as incomplete and preserves it.

Source checkouts, external selected binaries, other generations, external caches,
global/user Claude settings and services are not removal targets. Internal
symlinks are unlinked without following their target; escaping links, special
files, hard links, shared writable entries and nested mounts cause refusal.
Directory descent uses Linux `openat2` with `NO_XDEV`, `NO_SYMLINKS` and
`BENEATH`. A host without this kernel interface refuses application.

## Interrupted and uncertain state

An interrupted preparation without its final receipt does not establish enough
ownership to authorize recursive deletion. Keep it for inspection; prepare a new
generation with the accepted `--prepare --rebuild` command. There is no broad
prune, force flag, service uninstall or process-name kill.

Process inspection covers same-account executable/cwd/root links, command and
environment paths, mappings and open descriptors. A protected same-account
service can make the result uncertain even if it is unrelated. Retain that
refusal and use an account/environment where the necessary inspection is
available; do not relax system security settings to make cleanup pass.

If deletion is interrupted, some selected assets may already be removed. The
command does not roll those deletions back. Preserve the result and residual
directory for manual inspection; a partial generation must never be relaunched.
Do not run preparation, profile switching or new pilot launches concurrently
with removal. Process inspection is a point-in-time check, not a lock shared
with every other process running as the operator.
