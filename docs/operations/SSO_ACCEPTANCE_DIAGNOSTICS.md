# Genuine SSO acceptance diagnostics

SOU-70 owns the disposable acceptance drivers and evidence, not production
authentication semantics. Both existing Linux workflows still require genuine
Keycloak, Chromium, TLS and SQLite/PostgreSQL lifecycle assertions. CodeQL, audit,
platform and other required checks remain unchanged. This is not Phase 4 completion.

## Run one focused fresh fixture

Use an owned Linux x86-64 runner with Docker access, Rust/Cargo, Python 3 with venv,
NSS `certutil` (`libnss3-tools`) and Chromium OS dependencies. The existing workflows
install those dependencies. On a prepared Linux machine, from a fresh checkout:

```bash
bash scripts/sso-acceptance.sh oidc sqlite 1
# Other supported pairs: oidc postgres, saml sqlite, saml postgres.
```

This command creates a separate Python environment, installs the same pinned
Python packages/Chromium as CI, builds the real gateway/bootstrap example with
`--locked`, and calls the existing protocol driver. It does not install system
packages or alter OS trust. Existing Python environments may instead run
`bash scripts/keycloak-oidc-acceptance.sh postgres` or
`bash scripts/keycloak-saml-linux.sh postgres` directly.

Each invocation owns a fresh bridge network, loopback ports, Keycloak realm,
database, certificates, HOME/NSS store, processes and browser contexts. It never
adopts an existing database or operator IdP. Keycloak and PostgreSQL images remain
pinned by digest. Only the newly returned Docker IDs are cleanup targets;
containers are removed with their volumes before their network is removed.
Readiness requires real HTTPS discovery, SQL readiness and gateway `/readyz`.
Readiness alone never constitutes acceptance.

The driver has a 900-second total execution budget, retaining the existing
90-second OIDC and 45-second SAML browser action/phase bounds. A failed navigation
is detected while pumping browser events instead of waiting blindly for the next
selector. SIGTERM/SIGINT and the total deadline unwind the same owned cleanup as
an assertion failure. Cleanup commands have individual bounds. The batch wrapper
allows 960 seconds then sends SIGTERM, allows 60 seconds for cleanup, and records
an incomplete result if a forced stop is necessary. SIGKILL, runner loss or an
unresponsive Docker daemon cannot promise successful cleanup; inspect the retained
IDs on that owned runner. Never run a global prune or kill Java/Chromium by name.

## Read evidence before rerunning

OIDC writes `target/oidc-evidence/batch-*/`; SAML writes
`${SAML_EVIDENCE_DIR:-target/saml-evidence}/batch-*/`. Each contains `batch.json`
and numbered run JSONs. A destination must be fresh; previous evidence is not
overwritten. Workflows upload only these JSONs and retain them for 30 days.

Reports include exact source commit, tracked diff hash/dirty bit, relevant source,
configuration and binary hashes, Python/package/browser identities, pinned images,
actual container image IDs, backend and monotonic phase durations. Phase transitions
cover fixture startup, IdP discovery, database/gateway readiness, redirect,
credentials, callback, server session and logout. All login attempts are retained,
including a permitted failed transport attempt. Navigation statuses are capped at
12 and network failures at eight per attempt; phase entries at 256.

Failure diagnostics contain only fixed location/error categories, numeric HTTP
statuses, callback-request/response booleans, process exit state, container state/
OOM flags and allowlisted server errors. Log reads are capped at 64 KiB and login
errors start at that attempt's log offset. Expected earlier refusals cannot poison
a later login's diagnosis. Passwords, authorization codes, tokens, cookies, SAML
assertions, bodies, raw URLs, raw logs, traces, screenshots and environment dumps
must not be attached. Private temporary fixture material is deleted by owned
cleanup. Successful acceptance still requires every original assertion and cleanup.

| Evidence | Interpretation and next step |
| --- | --- |
| Callback request observed, response absent | Server may already have consumed it. Fail; never retry this login. |
| Only `ERR_NETWORK_CHANGED`, owned pre-callback location, no authentication/server error | Existing single retry is allowed and the failed attempt remains in the report. |
| Signature, replay, issuer, audience, authorization or session error | Preserve refusal/product witness; do not retry it away. |
| Connection refused, TLS error, process exit or OOM | Inspect the owned fixture phase and health; no authentication retry. |
| Timeout without classified network failure | Unclassified failure; retain phase/timeline and investigate, do not call it a flake. |
| Source/configuration hashes differ | Separate this run from historical or stale PR evidence. |

Both drivers previously checked a callback **response** before allowing a retry.
An already sent callback whose response was lost was therefore misclassified as
pre-callback. The deterministic negative controls failed on accepted main and pass
with the new request-side marker. This is a driver defect; it does not establish
that the historical browser timeout was caused by a production authentication bug.
The accepted OIDC network-change rule remains single-use and narrowly classified;
SAML gains no additional retry category. Assertions and expected refusals are never
retry triggers.

## Focused CI and bounded repeatability

The existing `keycloak-oidc` and `keycloak-saml` workflows accept manual `backend`
(`sqlite`, `postgres`, or `all`) and `runs` (`1` or `2`) inputs. PR runs still test
both backends once. For an investigated failure, select the failed job's protocol
and backend, preserve its first artifact, and run only that owned job. GitHub's
individual job rerun is also suitable for an unchanged source; do not use “rerun
all jobs” as a diagnostic probe. Rust caching, image digests and workflow timeouts
are unchanged. No extra full CI matrix is launched by the driver.

For a repeatability witness, declare the batch first (at most two independent runs
per selected pair). Both fresh fixtures execute even if the first fails; one green
run cannot erase a failed first run. `batch.json` separately counts `completed`,
`failed`, `incomplete` and `skipped`. Completed requires exit zero, all assertions
passed and successful cleanup. Cancellation leaves remaining planned runs skipped.
Any failed or incomplete run makes the batch nonzero. A few greens are evidence
about that bounded batch, not universal flake elimination.

Driver controls:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_keycloak*.py' -v
python3 -m unittest discover -s scripts/tests -p 'test_sso*.py' -v
```

The Linux signal test independently starts and reaps a real child and removes its
new directory after SIGTERM and deadline signals. It is explicitly skipped on
Windows. Unit controls use synthetic observations and never substitute for the
genuine vendor/browser jobs. See the [SOU-70 evidence record](evidence/SOU_70.md)
for exact sources, outcomes, historical classification and remaining gaps.
