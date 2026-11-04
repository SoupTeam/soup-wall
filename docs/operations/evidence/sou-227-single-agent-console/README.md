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
