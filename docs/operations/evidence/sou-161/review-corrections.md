# Corrections to the early Draft evidence

The review of source `fd059e21` identified an incomplete 5/19 run, an ambiguous
inspection failure label, a missing installed hardlink control, and an overstated
postcommit-result-loss label. The original reports remain unchanged.

Attempt 1 did not retain the failing typed inspect reply. Its exact cause cannot
be recovered, and `inspect_exposed_arguments` does not by itself establish a
content disclosure. The current qualifier separates nonzero inspection exits from
successful-response redaction checks, retains only bounded finite diagnostics,
and explicitly reconciles ended-run inspection with the daemon-written Ask verdict,
its exact audited pending binding and
zero admitted writes/target effects. Arbitrary inspection failures remain failed
qualification, never a passing redaction result. Existing lifetimes and caps are
unchanged.

The old `postcommit-result-loss` cases in attempts 2 and 3 received the operation's
successful tool result before interrupting the host. Their supported conclusion
is interruption after delivery with committed bytes preserved. They do not prove
model-facing result loss. The current case is named `interruption-after-delivery`,
requires the successful result already observed, and explicitly reports
`tool_result_lost: false`.

The installed hardlink control links the selected target to an owned alias
outside the output root, invokes the installed entry, and independently checks
both names, identities, link counts and byte digests. No run or execution authority
may be created. The final inventory retains every expected, attempted, passed,
failed and incomplete case.

CodeQL alert 221 followed the constant private directory name into nonce-file
handling. Actual grant nonces were already randomly issued. Each run now uses a
fresh generated private home identity, records it in run metadata and verifies
that it is an exact child of the selected run. No security alert was dismissed
or query suppressed; the final aggregate CodeQL result must independently pass.

Attempt 4 retained the safe `run_ended` diagnostic and full 23-case inventory.
Its reconciliation wrongly expected `native_call: ask`, although classifier-origin
Ask creates native pending before `native_call`. The corrected witness matches
the inspected daemon verdict to `native_approval_requested` by pending identity
and binding, retains this finite reconciliation before assertions, and continues
to require zero admitted writes and unchanged target bytes.
