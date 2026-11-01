# Third failed witness and selected-server refusal correction

Run https://github.com/SoupTeam/soup-wall/actions/runs/40817747346,
job 123262767347, source `0b6ee53f35e7304720c72863b943989ad26eecfa`.
Artifact 12873018143 archive SHA-256:
`fa16cf914498dcb671e00e8f24c084c369416c22a536a7f4d57c77d53c0316d0`.
Download hash and CRC checked; JSON files retained unchanged.

Four 50/200-file cases passed. B18-benign has five true predicates: classifier
unknown and truncated, zero execution receipts, tool error and invocation withheld.
Only the generic policy_unconfirmed_ask expectation fails. Actual collector
telemetry independently records unknown=true, read_only=true, verdict=ask.
Cleanup passed. The old artifact does not expose the actual refusal string.

Source reconciliation: `mcp/admission/real_server.rs::admit` evaluates
`known_read_only` before native admission and before its approval flow. Unknown
semantics set this false. With the configured nonzero approval wait, the branch
returns `classifier_unknown_approval_unsupported` through `withheld`. This is
distinct from the generic `admission.rs` loop's `policy_unconfirmed_ask` response.
The earlier generic operator-approval suggestion does not apply to this selected
original-server path; no approval workaround is introduced.

The harness now requires exactly one text block with the complete selected-server
refusal message and isError=true, while preserving the other five predicates.
Unrelated Deny, timeout, generic Ask, no-approval classifier_ask, and appended text
are rejected. The reason is also included in bounded diagnostic codes. Production
code, limits, classifier and policy remain unchanged. The fixture now represents
the source contract; local fixture tests are not a native runtime qualification.

Validation: 16 Python tests OK with one platform skip; generated workflow check
passed. Independent review and a new exact-source run remain necessary to confirm
201/256 refusal, ambiguous-body and copied-wire controls. The ten production false
refusals remain unresolved; Draft/In Progress remains appropriate.
