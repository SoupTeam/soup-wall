# Prepared Linux pilot audit retention and export

The prepared Linux runner selects the existing SOU-84 bounded audit store for
its own newly created enforcing daemon. Existing installed daemon settings,
policy, original read-only profiles, native authority and sticky shared-host
risk are unchanged. Running the plan alone creates no audit storage.

## Limits and lifetime

Each explicit `pilot-run.py --run` selects retention version 1 with four 64 KiB
segments, a 512,000-byte owned audit-store cap and a 64 KiB serialized-record
cap. Metadata and writer-lock allowance are included in that store cap. These
are the existing engine's limits, not a new retention implementation. The
private run receipt records the source commit, preparation-selection digest,
binary, policy, merged registry and retention-configuration identities. The
plan reports the selected limits before execution.

The random run directory is mode `0700`; receipts and audit files are `0600`.
Only this run's daemon writes this store. Ordinary completion, cancellation
and failure stop owned processes before cleanup. The runner then removes
tokens, raw host/daemon logs and runtime settings, retaining only `audit/`,
`audit-run.json` and `audit-finished.json`. The completion report gives the
directory, run ID and an observed loss-state snapshot. `manifest_observed`
is metadata observation, not proof that every segment is intact; export
performs the existing full verification. `unavailable` means unknown evidence,
never zero execution.

An explicit authenticated stop retains its existing private stop/recovery
receipts and credentials as before, so a repeated stop can be verified. An
unconfirmed process cleanup also retains private recovery state and fails.
Treat these directories as sensitive; do not share or delete them until the
existing stop/recovery procedure confirms owned processes have stopped.
SIGKILL or power loss can omit `audit-finished.json`; export labels that run
active or interrupted. Audit housekeeping never resets a live session.

Limits apply **per run**. There is no automatic sweep of unrelated directories
or aggregate quota across arbitrarily many separate runs. After privately
reviewing/exporting a stopped run, the operator explicitly removes that exact
owned directory if it is no longer needed. Do not retain unneeded run histories
indefinitely. Do not change limits inside an existing store; the manifest pins
them. Storage fault recovery remains the accepted
[SOU-84 procedure](AGENT_AUDIT_RETENTION.md).

## Explicit sanitized export

Use the exact directory and run ID from the selected run's report. Create a
new owner-private output directory **outside the run directory**:

```sh
mkdir -m 700 "$HOME/pilot-audit-review"
python3 -B scripts/pilot_audit.py \
  --run-directory /absolute/soup-wall-run-RUN \
  --run-id RUN \
  --output "$HOME/pilot-audit-review/summary.json"
```

Export is explicit, bounded to 128 KiB and 128 decision references, and never
overwrites an output. It reuses SOU-84 segment verification and the SOU-75
projection. A bounded raw intermediate exists only in an owner-private
temporary directory and is removed on success or failure. The shareable
summary contains only validated identities, fixed event/verdict labels,
report-local correlation aliases, booleans and loss markers. It excludes raw
arguments/results, prompts, tools' arbitrary names, rules' arbitrary text,
credentials, native authority, private paths and unrelated user history.
No provider is contacted and no daemon is started, stopped or repaired by
export. A live export is a snapshot; concurrent manifest changes can refuse
with a finite failure and require an explicit retry.

Intentional rotation, missing/corrupt segments, partial tails, unknown records,
missing call/result linkage, active/interrupted runs and reference truncation
remain incomplete evidence. A stale run ID, replaced store, unsafe ownership,
link/FIFO, changed receipt or unsafe output refuses. Missing evidence does not
prove no execution. Allow does not prove execution; a released result does not
prove model consumption. Owner-editable local hashes are not authentication
against the owner. The original raw SOU-84 export remains private and is not a
shareable support summary.

Required native audit failure still refuses admission/result release through
`native_audit_unavailable`. Rotation can prune old evidence; it does not excuse
failure to retain current required evidence. Legacy hook write behavior is
unchanged. No exception, receipt, policy floor, timeout or witness is relaxed.

## Qualification

The existing native Ubuntu 24.04 preparation lane runs
`qualify-prepared-pilot-run.py --audit-retention` with genuine selected Claude
and original filesystem/Git servers. The added scenario rotates the actual
run store, samples active concurrent exports, verifies pruning and the byte
cap, checks the same native daemon instance, and requires useful original-server
continuation and the existing denied-mutation witness. Other lifecycle controls
verify that only bounded audit evidence survives ordinary cleanup. The existing
SOU-84 owned acceptance separately qualifies store reopen/restart, native
fail-safe controls, rotation and export; it does not substitute for the prepared
host scenario. Only sanitized reports are uploaded. Raw traces, tokens,
workspaces and intermediate exports remain private.

Python fixtures exercise stale/changed identities, linked/shared files, FIFOs,
missing/corrupt/partial evidence, unknown schema, bounded projection and secret
canaries. POSIX fixture results on macOS do not qualify Linux containment or a
running Linux daemon. Hosted evidence must bind the final clean source. The
provider is an owned scripted loopback service; no paid calls or live-model
effectiveness is claimed.
