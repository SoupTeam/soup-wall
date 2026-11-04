# SOU-227 acceptance evidence

Implementation source: 4a27a93019180697a6dd8064b766365b66b3eee6. Both final
native workflows succeeded at this exact source; the retained reports are
independently verified against Git rather than trusted solely from job status.

- [Browser/Console/Agent run 41862618813](https://github.com/SoupTeam/soup-wall/actions/runs/41862618813):
  11 individual policy browser tests, zero skips and zero callback/page errors;
  real SQLite lifecycle 19/19 and PostgreSQL lifecycle 20/20 checks.
- [HTTP/PostgreSQL/recovery run 41862617056](https://github.com/SoupTeam/soup-wall/actions/runs/41862617056):
  shared immutable readback, cold/partial read-only schema, current authorization,
  sequence/group-ownership conflicts and durable retry controls. The required
  PostgreSQL HTTP test ran with one pass and zero ignores. Real encrypted
  recovery demos passed 31/31 checks on each backend.
- Final local workspace: 2024 passed, 0 failed, 15 explicit environment-dependent
  ignores; workspace/all-target Clippy -D warnings and fmt passed. No required
  native PostgreSQL/browser control was substituted with a local ignore.

The real browser authoring cycle creates and reviews exact immutable YAML and
server digest, approves it, issues a signed policy and independently observes
real Agent application. It loses a committed response, retries the same key
without an extra sequence, and rolls back through a higher-sequence baseline
with its matching applied acknowledgement. Real hook effects are deny → allow
→ deny. Role/Agent revocation and unrelated tenant isolation remain enforced.

## Current retained proof

native-final.json binds both final run/artifact IDs, artifact SHA-256, all test
names/counts, local qualification identity and report hashes. Both artifact ZIPs
were checked for CRC, duplicate/path traversal entries and bounded sizes. Every
reported source-file hash was independently matched through git show at the
qualified commit: 55 browser source files and 287 backend source files.
final-sqlite-report.json and final-postgres-report.json retain the exact clean
source/tree, synthetic recorded deployment identities, all checks, configuration
hashes and actual binary hashes. No credential, signing seed, raw private log or
database connection string is published.

The managed-group demo's legacy recovery_schema:28 report label is stale. The
strict inventory at the exact qualified commit declares PostgreSQL schema 30
and recovery executes against that inventory. The stale label is disclosed in
the final ledger; it is not used as the schema authority. This task adds no
persistent table, migration or recovery inventory entry.

## Retained attempts and limitations

local-attempts.json includes failed formatting/driver attempts, the macOS
scratch-only Chrome launch failure, EAGAIN failures in unchanged agentfw CLI
fixtures and subsequent passing sequential workspace runs. Local browser launch
ran zero tests and is not claimed as acceptance. No guard or target test was
weakened to accommodate those environmental failures.

native-attempt-1.json, sqlite-report.json and postgres-report.json retain
initial source 32946036 proof. native-qualified-2332a752.json and the two
qualified-2332a752-*-report.json files preserve the subsequent source 2332a752
proof after the duplicate dialog-listener fixture error was fixed. These older
reports are historical only; they are not substituted for final source 4a27a930.
The final source also distinguishes entirely cold SQLite (empty/404 with no DDL)
from partial schema (explicit 503, no repair or false empty-history claim).

The last update changes documentation/evidence only. Final current-main Ready,
security/admission and merge remain maintainer-owned.
