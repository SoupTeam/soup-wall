# Linux Keycloak SAML lifecycle checkpoint, 2026-10-15

Source commit: `e182e7b5e7427e054d155d5680acfedcded329a8`, based on accepted
main `786003d`. [PR #125](https://github.com/SoupTeam/soup-wall/pull/125)
implements SOU-51. This is author-generated disposable Linux evidence;
independent review and customer deployment acceptance remain separate.

## Results

[Workflow run, attempt 1](https://github.com/SoupTeam/soup-wall/actions/runs/38745036002/attempts/1)
completed successfully on Ubuntu 24.04 with genuine Keycloak 26.8.0 and
Chromium 153.0.8010.12. Both backends completed owned cleanup before success.
An explicit [second attempt at the same source](https://github.com/SoupTeam/soup-wall/actions/runs/38745036002/attempts/2)
also completed successfully for both backends. This repeatability check used
fresh disposable resources; it was not an automatic retry inside a passing run.

| Backend | Passing check observations | Retained report |
| --- | --- | --- |
| SQLite | 68 / 68 | [Sanitized JSON](SAML_LINUX_SQLITE_2026-10-15.json) |
| PostgreSQL | 75 / 75 | [Sanitized JSON](SAML_LINUX_POSTGRES_2026-10-15.json) |

The shared Gateway binary SHA-256 is
`b38dbd1f4f846d87d7d3b95e1efd9a84ba422b29ca8c974fba87c0684838fd00`.
The bootstrap helper SHA-256 is
`8366058b1ede80fd17a10668549861642f4f3a6fc1a245c12fdb117b46bbf919`.
The downloaded artifact ZIP digests matched GitHub's published digests. Every
reported source hash was compared against `git show` at the source commit above.
The reports retain the exact image digests, metadata/certificate hashes,
configuration hashes, browser version and AWS-LC provider identity. Later
documentation-only commits do not change the tested source or binaries.

The real browser crosses from Keycloak `localhost` to Gateway `127.0.0.1` on
the SAML POST. Positive controls include local Owner and Analyst authorization,
session refresh/logout, active session and pending SAML request survival across
Gateway/PostgreSQL restart, local membership and token revocation, and fresh
login after explicit vendor certificate replacement. Negative controls include
missing browser binding, replay, a mismatched pending request, NameID mutation
to another authorized local member, unprovisioned/no-membership identities,
TLS hostname/CA rejection, an untrusted new vendor key, a retired old key and
a genuinely expired vendor assertion. Native genuine-vendor corpus tests also
verify audience, expected issuer, ACS/correlation, signature and expiry checks.
Encrypted assertions remain rejected; vendor-wide SAML SLO is not claimed.

## Failure history and reproducibility limits

Earlier attempts are not counted as successful acceptance:

| Source / run | Observation and disposition |
| --- | --- |
| `a1d91d1`, [run](https://github.com/SoupTeam/soup-wall/actions/runs/38741327160) | Post-rotation administration failed. The retired signing key also signed the old admin access token. |
| `4152e7e`, [run](https://github.com/SoupTeam/soup-wall/actions/runs/38742006828) | Reading the full client representation alone did not solve authorization. The driver now reauthenticates its private realm administrator after rotation. |
| `a941559`, [run](https://github.com/SoupTeam/soup-wall/actions/runs/38742882123) | A fresh login timed out after the short-expiry control. The normal assertion lifetime is now explicitly reset to 300 seconds instead of omitting the attribute from an update. |
| `a923e01`, [run](https://github.com/SoupTeam/soup-wall/actions/runs/38743621142) | SQLite passed; PostgreSQL timed out at Analyst login after restart. |
| `0d921fd`, [run](https://github.com/SoupTeam/soup-wall/actions/runs/38744331617) | SQLite passed; PostgreSQL again timed out before an observed ACS response. No Gateway validation error was observed. |

The last two timeouts do not establish a production authorization defect or a
proven fix. The driver now retains bounded IdP/callback diagnostics without
automatic login retries. The complete successful source run above remains
distinct from those failed attempts; independent reproduction should retain
any recurrence rather than discard it or extend timeouts until it passes.

Local Windows checks passed Rust formatting, workspace clippy and workspace
tests, followed by focused SAML regression checks after the final Rust change.
The full Python suite ran 541 tests with 86 skips and three Windows-specific
failures in unchanged Linux-alert/SOU-54 fixtures (POSIX mode bits, symlink
privilege and slash normalization). The benchmark suite passed 44 tests with
18 environment skips. Linux CI results and optional/platform checks must be
read from the PR checks; local skips are not acceptance evidence.

See the [reproduction and recovery procedure](../KEYCLOAK_SAML_LINUX.md).
