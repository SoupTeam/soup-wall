# Legacy host fix with current main

Merged accepted main `4ed9bd569265fb34e279e95275157d0eec6799ac` into legacy fix `d5c7cb53691014d240d5f28ffee03de62b0acee1` without conflicts. This supplies the SCIM example and standard-user Windows fixtures required by the newer base-branch workflows; no shared-host downgrade path was reintroduced.

Full isolated workspace: 1283 passed, 0 failed, 10 intentional ignores. Clippy with `-D warnings` and formatting pass. Driver offline tests: 6 passed, 1 Docker opt-in skipped. SAML's existing bounded transport diagnostics/retry now cover the full navigation step, including errors thrown before waiting for the callback; it still permits at most one explicitly observed pre-ACS ERR_NETWORK_CHANGED and never retries signature, vendor credential or local authorization failures.

The legacy fix red/green evidence is in [the dedicated report](../sou-63-legacy-host-rejection-2026-10-17/README.md).

## Independent Cargo audit blocker

The new [audit job](https://github.com/SoupTeam/soup-wall/actions/runs/39000079518/job/117300953995) reports RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369 for transitive `zip 8.6.0`. That same version is present in main `4ed9bd569265fb34e279e95275157d0eec6799ac`. The current published `candle-core 0.11.0` constrains zip to the 8.x line; advisory remediation requires >=9.0.0. This change does not add ignores, falsify dependency versions or silently replace the ML dependency stack. The dependency blocker requires a separately validated upstream/backport/dependency remediation; this report does not claim green CI or merge readiness.
