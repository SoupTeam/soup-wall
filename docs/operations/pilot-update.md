# Coordinated pilot updates

The update coordinator selects the Agent binary, runtime inventory, installed helper and prepared selection as one identified generation. It uses the existing Agent lifecycle and helper installation commands in an inactive private home. The prepared inputs are supplied locally and remain in their existing accepted storage. One atomic pointer selects the complete set.

Supported mutation target: native Ubuntu 24.04 x86-64, ordinary user, private local directories. The coordinator does not build, download, discover executables on PATH, copy provider credentials or change an existing selection. Other lifecycle commands remain available.

## Inputs

Keep two complete, reviewed local sets. Each set needs its prepared front-door prefix, all referenced runtime and profile files, complete helper archive, archive digest and exact source commit. The interpreter must be the protected executable recorded by the selection and supported by the helper. A matching version string is insufficient.

Retain these inputs while a set is selected or retained for rollback. Removing or changing an archive, prefix, interpreter or runtime file invalidates that set. The bootstrap Agent home must contain the reviewed helper that provides `pilot update`; it remains the stable entry point.

Use a separate coordinator prefix outside the checkout and both prepared prefixes. Do not point it at an existing preparation directory.

```sh
umask 077
AGENT=/absolute/path/to/agentfw
ENTRY_HOME=/absolute/private/bootstrap/.agentfw
COORDINATOR=/absolute/private/coordinated-pilot
```

Generate an inventory without modifying the prepared set. Supply the independently reviewed archive digest and source SHA; do not obtain either from an untrusted inventory.

```sh
"$AGENT" pilot --home "$ENTRY_HOME" update inventory \
  --prefix /absolute/private/prepared-b \
  --component /absolute/private/helper-b.tar \
  --component-sha256 FULL_REVIEWED_ARCHIVE_SHA256 \
  --expected-commit FULL_REVIEWED_SOURCE_SHA \
  --version candidate-b > /absolute/private/b.json
```

The `sw-pilot-update-inventory/1` record binds the source commit/tree/tracked-files digest, archive, interpreter, selection, front-door receipt and each selected runtime/artifact path, size, mode and SHA-256. The preview reads these bounded records and hashes the files. It starts no selected program and creates no directory or journal. Full accepted profile/component validation is required during staging before activation.

## Preview and apply

```sh
"$AGENT" pilot --home "$ENTRY_HOME" update preview \
  --prefix "$COORDINATOR" --inventory /absolute/private/b.json
```

Review the result, then copy its exact `plan_sha256` into the confirmation:

```sh
"$AGENT" pilot --home "$ENTRY_HOME" update apply \
  --prefix "$COORDINATOR" --inventory /absolute/private/b.json \
  --confirm PLAN_SHA256
```

For the first selection, use the same sequence with set A. A subsequent application of B retains A as the previous set. Source, mode, hash or current-state changes invalidate the confirmation.

Staging requires the declared binary/archive allowance plus a 1 GiB reserve. The accepted capacity guard refuses unavailable capacity or quota observations and rechecks the reserve before each installation and selection. This observes space; it does not reserve it. Later permission, I/O or space errors retain the journal and do not authorize a partial set.

An active coordinated run or existing prepared-selection lease refuses the update. Surviving selected processes are checked through the accepted transition observer. The coordinator never kills them. Finish the owned run and retry the preview.

## Run and status

```sh
"$AGENT" pilot --home "$ENTRY_HOME" run --prefix "$COORDINATOR" \
  --state-root /absolute/private/run-state --prompt 'Read README.md'
"$AGENT" pilot --home "$ENTRY_HOME" status --prefix "$COORDINATOR" \
  --state-root /absolute/private/run-state --json
```

Both commands dispatch through the selected managed binary and verified installed helper. The prepared prefix is pinned by the binding; it cannot be overridden. A run holds the coordinator lease until its child exits and uses the existing supervisor and selection lifetime lock. Provider settings are forwarded only for that run through the accepted routing path; they are not stored in inventories or journals.

Successful selection, verification or rollback does not establish active protection. Only the existing authenticated live-status observation can do that.

## Rollback and recovery

```sh
"$AGENT" pilot --home "$ENTRY_HOME" update rollback --prefix "$COORDINATOR"
"$AGENT" pilot --home "$ENTRY_HOME" update rollback --prefix "$COORDINATOR" \
  --confirm ROLLBACK_PLAN_SHA256
"$AGENT" pilot --home "$ENTRY_HOME" update recover --prefix "$COORDINATOR"
"$AGENT" pilot --home "$ENTRY_HOME" update recover --prefix "$COORDINATOR" \
  --confirm RECOVERY_PLAN_SHA256
```

Rollback revalidates both complete sets and swaps the coordinator binding. It does not restore old sessions, approvals, daemon instances or tokens. Start a fresh run afterward.

| Recovery observation | Result |
| --- | --- |
| Before selection | Keep the previous complete selection; retain staged inputs for inspection |
| After selection | Verify the selected complete set and finish the journal without replaying installation |
| Conflicting state | Refuse mutation and preserve the operator's state |
| Nothing pending | Report the current observation; repeated recovery does not start work |

An interrupted journal blocks coordinated run/status until explicit recovery. Invalid or missing selected bytes are refused, with no fallback to another set. The journal and retained stage identify the failed attempt.

## Owned cleanup

`update cleanup --prefix DIR --generation ID --inventory-sha256 SHA` previews removal of an inactive complete stage. Repeat with its `--confirm PLAN_SHA256` to remove the Agent and helper through their accepted removal commands. Current and previous generations are protected. Extra files, directories, altered ownership or incomplete receipts cause refusal. Inventories, ownership records and the lifecycle lock remain for inspection; external prepared inputs are unchanged. Incomplete stages are retained rather than deleted by inference.

## Qualification

`scripts/qualify-pilot-update.py` consumes two identified prepared sets and an installed bootstrap entry. Without `--run`, it validates inputs and prints a read-only plan. With `--run`, it requires native Ubuntu and exercises install, useful original-server run, update, useful run, rollback and useful run using only an owned scripted loopback provider. It also injects five explicit staging/publication I/O interruptions, checks repeated recovery and removes eligible complete abandoned stages. These injections are not physical disk-full measurements.

The driver requires `--entry-agent`, `--entry-home`, `--inventory-a`, `--inventory-b`, `--fixture-root`, a new external `--output`, `--expected-commit` and `--expected-text`. Use only disposable owned fixture workspaces below `--fixture-root`, with matching README content in both selections. Its report retains source, binary, component and selection identities and individual unsuccessful attempts. A local unit-test result is not this native acceptance result.

The focused `mcp-real-filesystem.yml` dispatch accepts `coordinated_update_only=true`. It builds each source with the accepted native builder, prepares two disposable prefixes from explicit offline inputs, installs the current helper as the bootstrap entry, and runs the driver outside both checkouts. Set A is accepted commit `144512b3ed11f985c922d9911cba26f07599dea9`; set B is the exact dispatched head. Other focus flags must remain false. This development run does not replace ordinary qualification or admission.

Fixture preparation uses each installed helper and the explicitly selected `/usr/bin/python3.12`. Runtime classifiers therefore come from the private verified component tree. Parent ownership and modes are recorded before building; shared development-tool directories are not selected as trusted runtime inputs.

The native evidence includes a refused update during an authenticated live run, changed interpreter/binary/helper identity controls, five staging/publication interruptions, repeated recovery, eligible owned cleanup and useful original-server results before and after both transitions. A phase-level I/O injection is not a physical disk-full test.
