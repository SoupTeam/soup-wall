# Prepared-run discovery checkpoint

The standalone Linux command reads an explicitly selected state parent. It
does not create state, repair settings, start a daemon/host/helper, or contact a
provider. This is a draft checkpoint, not completed native Ubuntu qualification.

```sh
python3 -B scripts/pilot-runs.py --state-parent /absolute/selected/state
python3 -B scripts/pilot-runs.py --state-parent /absolute/selected/state \
  --run-id EXACT_PREPARED_RUN_ID --probe --probe-seconds 10
```

The prepared run ID is the suffix of `soup-wall-run-…`; the inner launcher's
32-character run ID is a different identity. Discovery does not search projects,
home trees, or other temporary directories. A selected parent may be an owned
private directory or a safe root-owned sticky directory, such as `/tmp`.
Linked ancestors, linked candidate directories, foreign ownership, unsafe
permissions, nonregular or oversized metadata, and changed identities refuse.

The `sw-prepared-pilot-discovery/1` JSON result separates `recorded` identities
from `observation`. Recorded source, selection and policy hashes are local,
owner-editable evidence. `completed_audit_only` describes the accepted completed
layout. `retained_stop_state` means stop/recovery authority must be preserved;
discovery does not authenticate a stop receipt or claim that its cleanup finished.
An active-looking record remains `active_or_interrupted` until an explicit probe.

`--probe` checks the launcher's process start identity, sealed memfd, exact
record bytes, executable hash and sealed configuration identity. It uses only
the selected `127.0.0.1` port and private tokens to query the accepted
`/native/v1/instance` and `/diagnostics/v1/protection` endpoints. Requests disable
ambient proxies and redirects, cap response bytes, and share a total deadline.
Nonce and instance mismatches, unavailable processes, and edited records are
unavailable, never healthy. Tokens, native authority material, host session IDs,
raw results and private logs are not printed.

The checkpoint projects authenticated daemon identity and mode only. Full
accepted diagnostic configuration/path-coverage validation remains pending.
Consequently **protection and execution coverage always remain `unknown`**,
including after a successful probe. An authenticated observation proves neither
model consumption nor execution, human approval, or live-model efficacy.

Defaults cap enumeration at 512 entries, results at 32 candidates, individual
metadata at 64 KiB, and output at 256 KiB. `--scan-limit` accepts 1–4096;
`--candidate-limit` accepts 1–64; `--probe-seconds` accepts 1–30. The executable
hash reader has a 512 MiB cap and observes the shared deadline. Reaching a limit
or missing a requested run sets `complete: false`. Enumeration is bounded in
filesystem order; returned runs are sorted by identity.

Exit 0 means a complete selected inventory, **not protection**. Exit 2 means
incomplete discovery or an unavailable candidate. Exit 1 means invalid input or
an unavailable parent. Unknown entries are counted without disclosing their names.

The focused regression and CLI demonstration use disposable Linux fixtures.
They do not replace the remaining native Ubuntu evidence: two simultaneous real
prepared runs, original pinned servers, daemon loss/restart, and unchanged state
and provider routing.

Reproduce the checkpoint against a clean committed source tree, using an existing
private Linux directory for the report:

```sh
python3 -B scripts/verify-prepared-run-checkpoint.py \
  --expected-commit FULL_COMMIT --output /private/owned/checkpoint.json
```

The report includes source hashes, individual fixture outcomes and explicit
remaining gaps. Even a passing report sets `native_acceptance: false`.
