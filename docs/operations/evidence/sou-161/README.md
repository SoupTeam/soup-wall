# SOU-161 installed private-output edit qualification

The corrected current-source native qualification passed all 23 expected and
attempted cases, with zero failed or incomplete cases. Qualified source:
`07a5f1d1b2b05162e1d1d7849af577e94b802202`.

[The native report](native-report.json) retains every case and its finite
witnesses. [Provenance](native-provenance.json) binds the source, installed Agent
and genuine Claude hashes to run `40533100725` and artifact `12747896293`.
The artifact SHA-256, CRC, exact three-member inventory, source commit and binary
correlation were independently checked before promotion. The installed Agent
binary equals the one built from `c6ab0da5`; the subsequent delta is qualifier
and evidence only.

The actual Ubuntu 24.04 x86_64 lane ran as a non-root operator with read-only
source, private writable scratch and a private network namespace. Genuine pinned
Claude Code 2.1.251 used only an owned scripted loopback provider. There was no
paid inference, live account or customer data. Runtime bytes, component and state
were installed outside the checkout.

The lane also passed 43 focused Rust controls (9 edit, 6 transport, 10 replacement,
5 native replacement HTTP, 13 creation), 5 finite/classifier controls, strict
Clippy and fmt without compiler warnings. The local macOS workspace independently
passed 1902 tests across 75 suites, with 13 existing ignored tests, strict
workspace Clippy and fmt. Existing classifier-runtime macOS tests emitted denied
xcrun cache-write diagnostics inside the sandbox and still passed; the sandbox
was not relaxed. This is development qualification, not shared Ready admission.

Both useful workflows used the genuine host for read → exact one-use Ask-approved
create/replacement → verified read. Independent byte/inode witnesses, matching
native admission/publication binding, zero adapter mutation dispatch and owned
process cleanup were required. The hardlink control preserves separate snapshots
of the target and an outside alias, including link count, identity and bytes, and
verifies refusal before a new run or authority exists.

No-approval, cancellation and daemon-loss controls retain successful redacted
inspection diagnostics and typed closed-run refusal. Their daemon-written Ask
verdict must match the exact audited pending identity/binding, with zero admitted
writes and unchanged targets. Arbitrary inspect errors remain failures.

`interruption-after-delivery` deliberately interrupts only after the provider has
received the successful tool result. It verifies committed bytes remain and the
host run reports failure without retry. It does **not** establish tool-result
loss or withholding. See [review corrections](review-corrections.md).

All intermediate results remain unmodified in
[the attempt inventory](attempts.json), including both failed attempts and their
original denominators. Reports that used the old postcommit-result-loss name are
explicitly scoped as interruption after delivery; no retroactive pass is invented.

CodeQL is independently required on the final PR head. The constant
private-home directory flow from alert 221 was replaced by a generated run-owned
home identity and checked metadata binding; no alert was dismissed or query
suppressed. Native evidence does not substitute for the final security result.

The original installed pilot remains read-only. Final shared Ready qualification,
admission, approval and main merge remain with the reviewer per Linear SOU-161.
