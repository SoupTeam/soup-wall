# SOU-187 installed single-file application evidence

The [operator guide](../../INSTALLED_EDIT_APPLICATION.md) describes the explicit
single-file scope and sole-writer boundary. Neither model output, review, Ask,
current matching bytes nor a readable journal receipt grants publication or
proves that an interrupted command completed.

`attempts.json` retains source/run/artifact/report correlation and superseded
attempts. `native-attempt-1.json` is the exact sanitized report downloaded from
immutable artifact 12933719608 after independently checking its ZIP digest,
source/tree, helper digest and binary correlation. All 36 controls passed on
`e03da1c5f08365528f3783476423a5e15b15de88`. The next helper revision adds the
37th actual concurrent-process control; its final result is recorded separately.

The native job uses Ubuntu 24.04, read-only source, scratch-only writes, dropped
capabilities/no-new-privs and a private loopback-only network. The installed
pinned Claude host uses the owned scripted provider only. Actual create, replace
and read calls precede offline review/application/revert; the operator trap has
zero requests and retained native tool/authority state remains unchanged.

The actual publication boundary is intercepted only in qualification: SIGKILL
before rename, after rename and after receipt fsync; file/directory sync errors;
readback, retained backup, indeterminate recovery and refusal of blind retry are
checked independently. The receipt-fsync kill specifically checks that a visible
receipt cannot reconstruct the private success acknowledgement withheld by the
interrupted process.

Private outputs, backup contents, run records, credentials and raw success
acknowledgements are excluded from public artifacts. These are disposable owned
fixtures; no real project contents or paid inference are used. Local records in
`local-checks.json` include the first nested-sandbox refusal, its enclosed retry,
platform skips and exact log/snapshot digests. Linux-only tests are not claimed
to have executed on macOS. This evidence does not replace the team lead's final
shared Ready checks, CodeQL, exact-candidate admission or merge decision.
