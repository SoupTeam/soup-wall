# Recover a pilot after a storage failure

Use the accepted native Ubuntu 24.04 preparation and
[prepared launch commands](PREPARED_PILOT_RUN.md) from a clean reviewed source
commit. Storage qualification uses disposable owned homes, original filesystem
and Git servers, and an owned scripted provider. It does not establish live-model
effectiveness or WSL2 qualification.

## What a failure means

| Boundary | Required behavior | Recovery |
| --- | --- | --- |
| Preparation before `current.json` replacement | Return failure, retain the old selected generation, remove only this attempt's unpublished temporary when possible. | Restore storage access, repeat the original preparation command without `--rebuild` to verify the selected generation. |
| Replacement completed but directory sync failed or was interrupted | Report publication/durability uncertainty; do not restore an old pointer or delete either generation. | Revalidate `current.json` using the normal preparation command. A failed verification requires reviewed preparation with `--rebuild`. |
| Private run configuration or authority cannot be persisted | Refuse before protected host startup. | Restore access to the owned state parent and start a new run. |
| Daemon cannot read an existing configuration | Refuse startup; do not substitute defaults for permission, I/O or decoding errors. | Restore the operator's intended configuration and access, then start a new run. |
| Native Linux admission/result audit append or durability check fails | Withhold admission/result. A failed legacy sink stays unavailable for that process. | Stop the owned run, preserve the audit, inspect its tail and start a new private run with fresh authority. |
| Run rendezvous/log write fails after host startup | Return failure and stop owned processes; host effects may already have happened. | Inspect the affected workspace and report before starting a fresh run. |
| Cleanup cannot close logs or remove private state | Report cleanup failure and retain remaining state; do not claim successful removal. | Confirm the recorded owned process identities have stopped, restore access to that exact owned directory and retry narrowly scoped cleanup. |

The append-only legacy audit is not a transactional database: restarting alone
does not repair a torn historical JSONL tail. Linux refuses a nonempty legacy
file without a final newline; this bounded check does not validate historical
JSON records. Preserve the old file as incident evidence. The prepared launcher
uses a fresh private home for each invocation. Linux native writes sync before
release; Windows legacy durability behavior is unchanged.
If using configured retained audit storage, use its existing documented recovery
command; this change does not add rotation or silently truncate evidence.

## Ordinary-user recovery

1. Stop retrying the failed operation. Keep its JSON report and any remaining
   private state private. `storage_failure` distinguishes full disk, quota,
   read-only storage, permission denial and I/O failure; `stage`, `host_started`
   and `cleanup` explain how far a run reached. A cleanup error may coexist with
   the original storage failure.
2. Check available space and quota on the filesystem containing the reported
   state parent. Restore space or access using your normal account/storage
   tools. Change permissions only on a directory you own and have identified;
   do not recursively chmod a home directory, remove unrelated files, kill by
   process name or relax sandbox/policy checks.
3. Repeat the exact original
   [preparation command](PILOT_RUNTIME_PREPARATION.md) without `--rebuild`.
   `reused` means the current generation passed verification. An interrupted
   generation is not evidence of completion. If verification fails, retain its
   evidence and use accepted `--prepare --rebuild` with the same reviewed source
   and inputs. Never edit receipts or copy an authority token from a failed run.
4. Run the prepared launcher first without `--run` and inspect its plan. Then
   start a fresh run. Old daemon/session grants are not reusable authority.
   Confirm a useful filesystem read and Git inspection before resuming work.
   A previous tool effect is not rolled back by withholding its result or by
   deleting runtime state.
5. For leftover prepared assets use the receipt-aware
   [cleanup guide](PILOT_CLEANUP.md). For a leftover private run directory, verify
   the recorded PIDs and process start identities have stopped before removing
   only that directory. If ownership, identity or state is uncertain, preserve it
   for diagnosis rather than guessing.

## Targeted qualification

Run from a clean exact source with the accepted selection and native build tools:

```sh
python3 -B scripts/qualify-pilot-storage.py --run \
  --selection /absolute/preparation/generations/GENERATION/selection.json \
  --expected-commit "$(git rev-parse HEAD)" --strace /usr/bin/strace \
  --output /absolute/private/new-storage-qualification
```

The manual real-filesystem workflow's `storage_recovery_only` option reuses its
single native preparation job and selected binaries. It skips the two broad
installed/prepared suites for that development run. Default qualification and
admission remain the responsibility of the existing gates and reviewers.
Missing cases, failed attempts and cleanup errors must remain visible in the
report. Deterministic syscall injection is scoped to an exact disposable owned
path and child process; it does not fill the host disk or prove physical
power-loss durability. Only an actually completed native run establishes its
reported platform behavior.
