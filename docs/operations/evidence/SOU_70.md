# SOU-70 reproducibility record

## Sources and predeclared execution budget

Assignment baseline: `fff8ba55a22f2d19b3a4554908571adc84a42fce`.
Accepted successor checked out for this increment:
`38c981bddbedfd2b06b80fb4c9af474b9b897ad3` (merged PR #168).
Git ancestry was checked locally. No open PR code was used as a dependency.

Baseline batch: one genuine run for each OIDC/SAML × SQLite/PostgreSQL pair,
using the existing unmodified workflows on `codex/sou-70-baseline` at that exact
commit. Repair batch declared before execution: two independent fresh runs for
each pair, using only the affected workflows. No rerun-until-green policy.

## Unmodified accepted-main baseline

| Protocol/backend | Job | Result | Retained artifact |
| --- | --- | --- | --- |
| OIDC PostgreSQL | [117442989743](https://github.com/SoupTeam/soup-wall/actions/runs/39048842800/job/117442989743) | completed, successful | [12107096839](https://github.com/SoupTeam/soup-wall/actions/runs/39048842800/artifacts/12107096839) |
| OIDC SQLite | [117442989925](https://github.com/SoupTeam/soup-wall/actions/runs/39048842800/job/117442989925) | completed, successful | [12106104301](https://github.com/SoupTeam/soup-wall/actions/runs/39048842800/artifacts/12106104301) |
| SAML PostgreSQL | [117442998629](https://github.com/SoupTeam/soup-wall/actions/runs/39048845653/job/117442998629) | completed, successful | [12107161465](https://github.com/SoupTeam/soup-wall/actions/runs/39048845653/artifacts/12107161465) |
| SAML SQLite | [117442998468](https://github.com/SoupTeam/soup-wall/actions/runs/39048845653/job/117442998468) | completed, successful | [12106966177](https://github.com/SoupTeam/soup-wall/actions/runs/39048845653/artifacts/12106966177) |

These jobs use actual Keycloak/browser exchanges and existing positive/session,
role/refusal, callback/replay and isolation assertions. The historical browser
timeout did **not** reproduce in this four-run baseline. Original reports have the
older diagnostic schema; newly added phase/runtime fields cannot be retroactively
claimed for these runs. Artifact retention expires 2026-11-16.

## Demonstrated driver defect

Before the repair, adding `callback_requested=True` to an otherwise retryable
network-change observation made both negative controls fail (two failures among
eight driver tests; one Docker-only opt-in skipped on Windows). The predicates
only checked callback responses. A sent request with a lost response can already
have consumed state on the server. Both now refuse a retry after a callback request,
regardless of whether a response was observed. Positive pre-callback transport
controls still pass. No production authentication or security expectation changed.

The phase-wait controls also demonstrate that a navigation failure stops the wait
before accepting stale UI, while an unclassified timeout remains a failure. The
repair retains the old timeout limits, adds an overall execution bound, and removes
the unbounded whole-log read from SAML diagnostics.

## Historical evidence is separate

[SOU-63's retained transport report](sou-63-ci-transport-2026-10-16/saml-original-failure.json)
records `ERR_NETWORK_CHANGED` on vendor navigation after an owned PostgreSQL
restart, with no ACS response. It does not have the new request-side marker and
does not prove that no callback was attempted. Its historical explanation about
network-interface changes is not a new current-main product finding.

[PR #156](https://github.com/SoupTeam/soup-wall/pull/156) discussion separately
records PostgreSQL OIDC/SAML timeouts and stale-source CI mismatches (missing SCIM
fixture and the then-unintegrated ZIP dependency remediation). Neither those
configuration/source mismatches nor the retained timeouts establish a current-main
production authentication defect. Required gates are preserved.

## Repair validation

Local Windows driver controls: 35 existing Keycloak tests, 34 passed and one
explicit Linux/Docker TLS opt-in skipped; 17 diagnostic/batch tests, 16 passed
and one real Linux signal witness skipped. Requests was installed at the existing
CI pin in a disposable environment; an earlier run without urllib3 failed and was
rerun only after installing that missing dependency. No local Linux, Docker, Rust
or genuine Keycloak pass is claimed.

The predeclared repair batch and Linux signal witness are pending. This record must
be updated with exact source and all outcomes before claiming completion. No
universal flake-elimination, Phase 4 completion or all-required-checks-green claim.
