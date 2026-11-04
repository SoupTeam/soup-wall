# SOU-227 evidence

Local proxy tests, fmt, all-target Clippy and JS/Python syntax checks are recorded
with exact snapshot and log hashes in `local-attempts.json`. Failed formatting
and browser-driver attempts are retained. The browser runtime could not launch
under the macOS scratch-only Seatbelt boundary (Chrome ProcessSingleton/socket
and crashpad attempted writes outside scratch); zero browser tests ran locally.
This is explicitly not a browser acceptance pass. PostgreSQL requires the native
PostgreSQL 16 fixture and is explicitly ignored locally, not replaced with 14.

Exact committed-source browser, real Console/Agent and PostgreSQL qualification
will be linked after completion. Reports contain sanitized checks and identities;
no credentials, raw private process logs or database URLs are published.

Initial Linux qualification at 32946036 passed both runs: 41848642387
(browser/real Console/Agent) and 41848649060 (SQLite/PostgreSQL HTTP controls and
recovery). The new browser suite ran 9 assertions without skips. Both backend
reports are retained and every recorded source-file hash was independently
matched against that exact Git commit. The real-process reports passed 16
SQLite and 17 PostgreSQL checks. They prove actual signed-policy application,
exact ACKs, lost-response reconciliation without additional sequence and
higher-sequence rollback. This evidence is attributed only to 32946036.

Inspection of the successful browser log found duplicate dialog-listener
callback exceptions in the fixture on repeated login. Registration is now once
per page and callback/page errors are hard failures. Requalification also checks
real hook deny/allow/deny effects and a duplicated initial deployment click.

The full workspace initially hit EAGAIN creating a process in unchanged
agentfw offline CLI controls. A sequential retry passed the entire workspace
and all-target workspace Clippy; both attempts and exact snapshots are retained.
No production source was changed to accommodate this environmental failure.

## Final browser and real-effect qualification

[Run 41851423556](https://github.com/SoupTeam/soup-wall/actions/runs/41851423556)
passed at exact source 2332a752f225a7dcc528041ce9c5ca18af82acdb: 11 new browser
tests, zero skips, zero callback/page errors; real browser/Console/Agent cycles
on SQLite and PostgreSQL with observed hook deny → allow → deny effects,
matching applied ACKs, same-sequence lost-response retry and higher-sequence
rollback. Final reports and source/configuration/binary identities are retained;
all 55 reported source-file hashes independently match that Git commit.

PostgreSQL HTTP/recovery run 41848649060 passed at 32946036. All Rust source,
Cargo manifests/lockfile and toolchain inputs are byte-identical between that
qualified server implementation and 2332a752; the later changes are UI/fixtures
and evidence and are exercised by the final browser run. The full workspace
passed 2024 tests with 15 explicit environment-dependent ignores; workspace
all-target Clippy -D warnings and fmt passed. The final update changes evidence
only. Final current-main Ready/security/admission and merge remain TL-owned.

The final cold-store parity review found that SQLite's lazily created managed
revision table could make a pre-enrollment GET return 503 while PostgreSQL
returned an empty inventory/404. SQLite now probes only sqlite_master and returns
the same empty results without DDL. The shared HTTP controls run this case first
on each backend and assert schema-object counts do not change. Local controls,
Clippy and fmt pass. The updated exact-source native qualification is recorded
separately from the earlier 2332a752 proof.
