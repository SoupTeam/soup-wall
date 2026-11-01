# Offline publication admission verification

The [exact-source report](offline-report.json) records **43 controls passed** on
Windows at source `26d536fad2ee9e3eee9a95e743261642805f5982`, tree
`594ebaa45bfb0c51d44b96aaa252110be0562e89` (use the report's tree as authority).
It records the raw-byte hashes of the consumer, entry point, regression tests,
qualification runner and release workflow. The report applies to that exact
source; subsequent CI setup/reporting corrections require fresh CI evidence.

The real public historical dossier is independently reconstructed from exact
Git-selected evidence bytes and remains **NOT_READY**. Its consumer result is
blocked with `dossier_not_ready`; current reconciliation also detects stored
legacy-verdict differences. The separate public scoped receipt retains the
matched 10/12 and three project 0/3 failures. Its private raw archive was not
accessed or requalified.

The final workflow's actual Bash publication blocks execute with owned local
`gh`, `docker` and `skopeo` spies. Negative controls make zero publication
attempts. Separate calibration controls reach both GitHub create/upload paths
and both GHCR tag/latest paths; no real publisher, tag or registry is invoked.
The API-refresh helper is reviewed wiring; these local spies substitute
controlled API context and do not contact GitHub. Stale-attempt refusal is also
an independent custody control.

[Retained attempts](retained-attempts.json) preserve the broader Windows checks,
including the [failed related-suite report](windows-related-attempt.json).
Those Unix descriptor and Linux path-fixture failures are not relabelled as
passing checks. Separate support controls passed 13 tests with one existing
skip; the source-change planner passed 18. Generated workflows are consistent,
and documentation links pass. No Rust source was changed; the broad Rust/native
matrix, Ready CI and final admission remain maintainer-owned.

All positive fixture approvals and full-product evidence in tests are synthetic
verifier controls. No real human review, license acceptance, live model result,
full-product readiness or publication permission is created by this report.
The external operator channel remains the authority for its explicit decision.

Reproduce with the [operator procedure](../../LOCAL_RELEASE_ACCEPTANCE.md).
Use `--consumer-only` for the focused offline consumer controls on Windows;
the default additionally runs the existing related producer/support suites.

The [first Draft CI attempt](https://github.com/SoupTeam/soup-wall/actions/runs/41098120193)
passed the existing Linux CI, dossier and scoped-identity steps, then failed
because its shallow checkout lacked historical Git objects for the real dossier.
The missing qualification artifact was also correctly reported as an upload
failure. The affected checkouts now fetch full history, and the reporter retains
a failed report even when prerequisites are missing. A focused regression covers
that reporting failure; no readiness or publication rule was relaxed.
