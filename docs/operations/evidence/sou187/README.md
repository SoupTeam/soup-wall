# SOU-187 installed single-file application evidence

The [operator guide](../../INSTALLED_EDIT_APPLICATION.md) describes the explicit
single-file scope and sole-writer boundary. Neither model output, review, Ask,
current matching bytes nor a readable journal receipt grants publication or
proves that an interrupted command completed.

`attempts.json` retains source/run/artifact/report correlation and superseded
attempts. `native-attempt-1.json` is the exact sanitized report downloaded from
immutable artifact 12933719608 after independently checking its ZIP digest,
source/tree, helper digest and binary correlation. All 36 controls passed on
`e03da1c5f08365528f3783476423a5e15b15de88`.

`native-attempt-2.json` independently verifies all **37/37 controls passed** on
`45eb64ce3b16b87745a4473638becd4069d5f9be`, including two concurrent operator
processes and exactly one successful publication. Its immutable artifact is
12934438880, ZIP SHA-256
`e0ae3bbf357c50c7373efe945bb182db067834e0617532aa914ff7087992abff`;
the exact report SHA-256 is
`47c50140c03f96d010420b9319cfd18c64953c943b731c33bbc283cdd673f74a`.
Source/tree, helper and binary correlations were independently checked before
running the finite report grader in the local enclosure. The second source
revision changes only the qualification helper, grading and guide; the product
code is unchanged. Later documentation/evidence commits are not represented as
native executions of a different source revision.

Both native runs passed all seven installed stages (application, read-only
review, edit runtime, stop, refresh, archive and quota). The final report records
107 unchanged-state observations, zero operator provider requests and zero
operator tool requests. All five actual injected faults retain indeterminate
recovery and refuse blind retry; all three kill controls exited by SIGKILL.

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
