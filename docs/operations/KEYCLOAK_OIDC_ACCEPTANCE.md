# Keycloak OIDC Console acceptance

SOU-32 exercises Console sign-in using the real Keycloak authorization-code
flow with PKCE S256. The Console at `/customer` offers an organization/workspace
form when no session exists. Credentials are entered only on Keycloak's page.
The Gateway exchanges the code, validates the signed ID token, and authorizes
the verified issuer/subject against active local workspace membership.

## Operator configuration

Enable the tenant store and configure `LLM_FW_OIDC_STATE_KEY` as a secret
base64url-encoded 32-byte value. Preserve it across Gateway restarts. Serve the
Console behind HTTPS. Configure an active organization OIDC connection with:

- The exact HTTPS Keycloak realm issuer, such as `https://id.example/realms/team`.
- A public OIDC client with the standard flow enabled and PKCE S256 required.
  Disable implicit flow and direct access grants.
- An exact allowed redirect URI: `https://console.example/auth/oidc/callback`.
- Locally provisioned issuer/subject identities and workspace memberships.
  An IdP role or email alone does not grant Console access.

The administrator supplies the organization and workspace IDs used by the
Console form. Existing `/auth/oidc/start` links continue to work. The browser
must retain the secure `__Host-llm-fw-oidc-flow` cookie through the callback;
passing a callback URL to another browser is rejected before state consumption.
Starting another login in the same browser supersedes the previous flow.

For an organization-operated private CA, set `LLM_FW_OIDC_CA_CERT_FILE` to a
readable PEM certificate bundle (maximum 64 KiB). It adds trust only to the
Gateway's OIDC HTTP client. Missing, empty or invalid configured certificates
fail the login; HTTPS and hostname verification remain enabled. Redirects and
ambient proxy configuration are disabled for this client. Without the setting,
the existing built-in public roots apply.

The browser receives an opaque, host-only, Secure, HttpOnly, SameSite=Lax
session cookie. The current local role is checked on server requests. Session
rotation requires the session-bound CSRF proof; the previous cookie is revoked.
Logout revokes the Console session and clears the cookie. It does **not** log
the user out of Keycloak or other applications. A subsequent sign-in can reuse
Keycloak SSO. The Console reports failed logout honestly and clears displayed
workspace data after successful logout or a 401 response.

Keycloak's [OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers)
and [TLS configuration](https://www.keycloak.org/server/enabletls) describe the
vendor side. This change does not add RP-initiated or back-channel IdP logout.

## Reproduce the disposable Linux/Docker drill

For phase diagnostics, owned cleanup, bounded batches and rerunning only the
failed backend, see [SSO acceptance diagnostics](SSO_ACCEPTANCE_DIAGNOSTICS.md).

Use Linux x86_64, Docker, the native Rust build prerequisites, Python 3.10+ and
NSS `certutil` (`libnss3-tools` on Ubuntu). The Keycloak 26.8.0 Linux/amd64 image
is fixed to `quay.io/keycloak/keycloak@sha256:ad1b0f0fa4bb5eff10f7a78eaafbb6d65b25431c1f824b0710836d74373a7dfb`.
Its upstream [26.8.0 release](https://github.com/keycloak/keycloak/releases/tag/26.8.0)
and [Apache-2.0 license](https://github.com/keycloak/keycloak/blob/26.8.0/LICENSE.txt)
apply; retain the image's included JVM/base-image license notices as well.
No customer account or paid service is required.

The realm import contains salted PBKDF2-SHA512 verifiers, not cleartext passwords.
The format and 210,000 iterations follow the pinned Keycloak
[credential model](https://github.com/keycloak/keycloak/blob/26.8.0/server-spi/src/main/java/org/keycloak/models/credential/PasswordCredentialModel.java)
and [hash provider](https://github.com/keycloak/keycloak/blob/26.8.0/server-spi-private/src/main/java/org/keycloak/credential/hash/Pbkdf2Sha512PasswordHashProviderFactory.java).
Generated cleartext remains in driver memory for the genuine HTTPS login.

Prepare the optional Python/browser tools in an activated virtualenv:

```sh
python3 -m pip install requests==2.34.2 cryptography==50.0.2 psutil==7.2.2 playwright==1.63.0
python3 -m playwright install --with-deps chromium
bash scripts/keycloak-oidc-acceptance.sh
```

The final command builds the production Gateway and disposable bootstrap,
starts the pinned Keycloak container on loopback, runs the genuine browser
flow, and writes a new sanitized result under `target/oidc-evidence/`.
The container has no capabilities or privilege escalation and mounts only
this run's realm and TLS files read-only. The owned container ID, child processes
and private files are removed on exit. The browser trusts the generated CA in
its disposable HOME/NSS database; no certificate-verification bypass or OS-wide
trust change is used on Linux. The Gateway uses its explicit CA file setting.

The [Linux vendor workflow](../../.github/workflows/keycloak-oidc.yml) runs this
same command and retains only the sanitized JSON. Check its actual result before
claiming acceptance. Token signature, issuer/audience and nonce mutation tests
remain focused Rust fixtures, separate from genuine vendor positive evidence.

## PostgreSQL identity parity (SOU-39)

After the same prerequisites, select the dedicated disposable backend:

```sh
bash scripts/keycloak-oidc-acceptance.sh postgres
```

The default command remains SQLite; `sqlite` may also be passed explicitly.
Both modes run the original vendor/browser checks and the new membership/token
revocation checks. CI runs both backends independently, retaining failed reports
as well as passing ones. A success on one backend does not stand in for the other.

The PostgreSQL Linux/amd64 service is pinned to
`postgres@sha256:ec9f656f17c8b4dfebf49e58cf5c46d493d4846d4ea6d8b85d0637f68ee33bfc`
(official PostgreSQL 16 bookworm image). The
[PostgreSQL License](https://www.postgresql.org/about/licence/) and the image's
bundled operating-system notices apply. The report records the observed server
version and image digest. The service has a generated database name and password,
a loopback-only published port, and TLS with an explicit ephemeral CA. Neither
the driver nor bootstrap accepts an operator database URL. The generated password
is passed through the Docker client's environment by name, never written to an
environment file or command-line argument. It is present in the owned container's
private configuration until cleanup; Docker administrators can inspect it. It is
not an evidence artifact.
Cleanup removes only the created container ID and its anonymous volume. The
PostgreSQL entrypoint retains the minimal ownership/user-switch capabilities
needed to initialize its volume and private TLS key; privilege escalation is
disabled. It is separate from the capability-free Keycloak container.

The production `llm-firewall migrate` command initializes the new database before
the asynchronous bootstrap provisions synthetic local identities. Normal Gateway
startup does not migrate. The bootstrap rejects repeat seeding into a populated
store. The drill also reruns migrations on populated identity/session state,
compares its complete selected rows privately, and checks that the active session
survives Gateway restart. It checks TLS use and refusal with an unrelated CA.
No schema reset or migration-version rewrite is performed.

Membership suspension/reactivation uses the public owner-only, CSRF-protected
Console API. An existing analyst session and a fresh login are refused while
suspended; a new login works after reactivation. Revocation remains effective
after Gateway restart. A genuine owner session also creates and revokes a machine
token through the Console API. A separate authentication helper calls the production
store authentication API before and after revocation and restart. This token
probe is a local store check, not a vendor login or external model request.
Console logout revocation is checked again after restart. Expiry is advanced by
SQL only inside this run's owned database, after verifying a fresh session works.

The selected scope is PostgreSQL-backed Gateway identity/session persistence.
Keycloak uses its disposable development realm store; PostgreSQL HA/failover,
SCIM, managed-Agent tables and Keycloak SSO logout are outside this drill.
The historical SQLite evidence below remains unchanged. New PostgreSQL acceptance
requires a passing report from this extended driver and independent review.

### Recorded parity run, October 14, 2026

[Workflow run 38520639174](https://github.com/SoupTeam/soup-wall/actions/runs/38520639174)
passed on source `abe80862462d1fe81c0135804480761f8380aa09`, Ubuntu 24.04,
Chromium 153.0.8010.12, Keycloak 26.8.0 and PostgreSQL 16.15. Both jobs also
passed five browser regressions, five driver safety tests and two bootstrap tests.
All original vendor checks were retained. No production identity/schema
incompatibility was observed in this selected slice; no migration was added.

| Backend | Passed checks | Cleanup | Unaltered report |
| --- | ---: | --- | --- |
| PostgreSQL | 50 | Passed | [PostgreSQL report](evidence/keycloak-oidc-postgres-2026-10-14.json) |
| SQLite | 43 | Passed | [SQLite report](evidence/keycloak-oidc-sqlite-2026-10-14.json) |

Each report's eleven source hashes were independently matched against that
commit's Git blobs. PostgreSQL report SHA-256:
`f34dde498bb07280fb53018978149e0c3dd670990a05fcf22fe2365c1f5e9f84`;
downloaded archive SHA-256:
`16a8dd008b07b03d44eb9bd07316fd48bdb2080102a1823690002f569eaa9a76`.
SQLite report SHA-256:
`625aff9b415cc78d054a281a96bf0aab0ad186f8910857510b9b83d55977eefd`;
downloaded archive SHA-256:
`ca415fd276d5676ef72aa682030965c376bb37417fcb7719dd977aedd748adf9`.

The initial run on `686132d` also passed its vendor checks but had a CodeQL
finding for a cleartext temporary environment file. It is superseded by the
recorded run, which passes the generated password only through the Docker client
environment and includes a regression preventing file/argument exposure.
Local Windows full-workspace testing also found an unrelated Agent lifecycle
failure at `crates/agentfw/tests/lifecycle.rs:214` and a hanging
`managed_lifecycle_restores_last_working_version` test. That run was stopped;
it is not recorded as passing. The remaining workspace crates, Clippy, focused
OIDC/bootstrap tests and Python suites passed. These limitations do not replace
independent review or establish acceptance of other deployment slices.

## Recorded Linux acceptance, October 13, 2026

[Workflow run 38414056010](https://github.com/SoupTeam/soup-wall/actions/runs/38414056010)
completed all 27 vendor/lifecycle checks and owned cleanup on Ubuntu 24.04,
Linux/amd64, with Chromium 153.0.8010.12. Five Console browser regressions and
the credential-import regression also passed in that job. Source:
`2ffe8200547bd2107de5b63d30f2cbfc24871f66`.

The [unaltered sanitized report](evidence/keycloak-oidc-linux-2026-10-13.json)
records runtime, binary and configuration digests. Its seven recorded source
hashes were independently matched against that commit's Git blobs. Report SHA-256:
`313aadcc883f99ad4f4ff52a129916dba619d8fbfcee7881d64a4f080240a290`.
Downloaded workflow archive SHA-256:
`5c723ec7a2d5cd039164c21b11907b4ce3f39c2f5286109ca580dda3f41ecb85`.

Genuine-provider checks cover S256 rejection, browser/state binding, callback
replay, membership and cross-organization denial alongside working login,
rotation, restart, logout and expiry. Focused signed-token negatives are separate:
`oidc_token::tests::rejects_nonce_audience_and_authorized_party_mismatches` and
`oidc_token::tests::rejects_wrong_issuer_and_tampered_signature_with_other_claims_valid`.
The latter adds explicit issuer/signature mutations with otherwise valid claims;
it does not mutate vendor-issued positive evidence.

## Optional Windows diagnostics

Use Python 3.10+, the native Rust build prerequisites, and the exact official
Keycloak/JDK archives pinned in
[the shared runtime table](KEYCLOAK_SAML_ACCEPTANCE.md#pinned-external-runtimes-and-licenses).
No Docker, customer account, provider API, OS certificate installation or real
workspace is needed. Install optional driver dependencies in a virtualenv:

```powershell
python -m pip install requests cryptography psutil playwright
python -m playwright install chromium
cargo build --locked -p llm-firewall --bin llm-firewall --example keycloak-oidc-bootstrap
python scripts/keycloak-oidc-acceptance.py --gateway target/debug/llm-firewall.exe --bootstrap-helper target/debug/examples/keycloak-oidc-bootstrap.exe --keycloak-zip C:/runtime-cache/keycloak.zip --jdk-zip C:/runtime-cache/jdk.zip --artifact-label YOUR_COMMIT --out C:/evidence/oidc-result.json
```

The output parent must already exist and the output file must be new. Runtime
archives are checksum-verified before extraction. The driver creates its own
realm, synthetic users, database, keys and certificates in an ignored temporary
directory. All listeners bind to loopback. Its browser is restricted to the two
owned HTTPS origins and pins this run's ephemeral TLS public key with Chromium's
SPKI option; the Gateway and HTTP driver verify the ephemeral CA chain normally.
No global trust settings or personal browser profile are changed.

The driver checks genuine browser login, local roles despite an IdP owner role,
denial of an unprovisioned user and unrelated organization, callback replay and
cross-browser rejection, secure session cookies, CSRF-protected rotation,
old-cookie rejection, Gateway restart, logout revocation and session expiry.
Expiry is advanced only in the new disposable SQLite database. Child processes
and private material are removed through the existing owned cleanup procedure.
Only checks, runtime/source hashes and limitations are exported. A failed run
is not acceptance evidence.

Run the focused offline and UI regressions separately:

```powershell
cargo test --locked -p llm-firewall oidc
cargo test --locked -p llm-firewall --example keycloak-oidc-bootstrap
python -m unittest discover -s scripts/tests -p test_console_browser.py -v
```

The browser fixture suite needs Playwright/Chromium and otherwise reports a
skip. It verifies missing/expired session behavior and both HTTP and network
logout failures. These UI fixtures do not substitute for the genuine vendor
drill. The Windows drill does not certify customer deployment, MFA, vendor SCIM,
Keycloak-wide logout, PostgreSQL failover or other operating systems.
