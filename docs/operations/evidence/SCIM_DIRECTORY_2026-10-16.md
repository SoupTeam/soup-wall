# SOU-57 independent SCIM client acceptance - 2026-10-16

## Outcome and reproduction

The pinned independent `scim2-client` 0.13.1 drove the production SCIM router and
storage APIs through a real loopback listener. SQLite passed 40 checks;
PostgreSQL passed 42, including fresh-schema verification, explicit normal
migrations and an observed verified TLS connection. Both completed owned cleanup.

[Reproduction and supported profile](../SCIM_DIRECTORY.md) documents exact
case-sensitive equality, supported discovery/PATCH attributes, directory-only
authority and the existing User DELETE deactivation contract. This does not
certify a customer IdP, complete RFC support, or a production deployment.

## Evidence identity

Source commit: `086e33adaff3ced7f2e514681970f713d8a3da31`.
[Exact-source Linux run 38937496864](https://github.com/SoupTeam/soup-wall/actions/runs/38937496864).

| Backend | Checks | Retained report | GitHub artifact ZIP SHA-256 |
| --- | --- | --- | --- |
| SQLite | 40/40 | [JSON](SCIM_DIRECTORY_SQLITE_2026-10-16.json) | `17bc5ead099d0900f3749156453f7fc2a313b8d481ab8a6b4a6986e436749d04` |
| PostgreSQL | 42/42 | [JSON](SCIM_DIRECTORY_POSTGRES_2026-10-16.json) | `5332ab9e8783646244cc66b1a270ade6037eaba401224dc420118a56fb11307d` |


The two JSON reports retain source SHA-256 values, fixture executable hash,
client source/version identities and per-case outcomes. Every source hash was
compared with `git show` at the recorded source commit, and each downloaded ZIP
was checked against GitHub's artifact digest before retaining its report.
The evidence commit changes documentation only.

## What was observed

- Actual client discovery and typed User/Group resources; create and duplicate refusal.
- Filtered lookup on all six supported attributes, count=0, pagination beyond
  the matching row, exact case behavior and a SQL-looking literal.
- Explicit SCIM errors for unsupported operators, compounds, attributes and types.
- Pathless replace, deactivate/reactivate, add/retry, replacement retaining an
  existing member, and filtered remove/retry.
- A valid first change followed by an invalid attribute or foreign member left
  the group unchanged. The equivalent User PATCH left its active state unchanged.
- Other-organization users were hidden, foreign groups were refused, revoked
  credentials stopped working and the other organization remained usable.
- User DELETE deactivated the retained directory record; Group DELETE made the
  group unavailable. The fixture process, temporary directory and owned database
  container were removed before reporting success.

## Native and supplementary verification

- `cargo fmt --all -- --check`, workspace clippy with `-D warnings`, and
  `cargo test --locked --workspace` passed locally on Windows. Focused SCIM
  regressions passed (6 unit, 3 tenant/API, 2 real-listener tests). Existing
  environment-specific/model tests retain their declared skips.
- Fixture-specific clippy passed after the final Rust helper changes.
- Benchmark Python suite: 62 tests, 19 declared skips, no failures.
- General Python suite on this Windows host: 659 tests, 91 skips, 2 failures
  and 3 errors in unchanged tests: Linux private-file mode expectations,
  Windows path separators/symlink privilege in SOU-54, and two SOU-56 TLS tests
  whose external OpenSSL executable is absent from PATH. These are not counted
  as passing local checks. Linux CI results are separate evidence.
- An intentional startup-refusal probe verified a nonzero exit, a failed report and no unverified cleanup success.
- Documentation link checker passed. Full repository CI is tracked separately in [PR #148](https://github.com/SoupTeam/soup-wall/pull/148); no all-checks-green claim is inferred from this focused report.

## Earlier failures retained

- Initial source `b574985`: the fixture incorrectly treated the migration-created
  bootstrap organization as foreign populated state. Both CI backends stopped
  before client execution. This was fixed by recognizing only the expected
  bootstrap organization while refusing tenant or SCIM records/credentials.
- A subsequent local Windows attempt failed before listener startup because
  environment filtering omitted uppercase `SYSTEMROOT`. The fixture now matches
  retained environment variable names case-insensitively. The next local run
  passed 40/40.
- Source `691a8e2`, [run 38936565885](https://github.com/SoupTeam/soup-wall/actions/runs/38936565885):
  Linux SQLite passed 40/40; PostgreSQL exited before readiness because the new
  fixture had not explicitly run the production migration API. The owned
  database driver now proves no public tables, then the helper invokes normal
  migrations before opening the runtime store.
- Source `37e18b9`, [run 38937143369](https://github.com/SoupTeam/soup-wall/actions/runs/38937143369):
  both backends passed (40/42). The subsequent final source tightens failed-run
  cleanup reporting: filesystem absence alone no longer proves Docker cleanup.
  Passing runs still require all cleanup callbacks to succeed. Old failed-run
  cleanup fields should not be treated as independent proof of container cleanup.

There are no hidden automatic retries. Each attempted run has its own evidence
path/run identity; a failed attempt is never changed into a passing report.
