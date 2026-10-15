# Genuine Keycloak SAML lifecycle on Linux

This disposable acceptance procedure uses real Keycloak metadata and assertions,
Chromium, the production Gateway and SQLite or PostgreSQL. It complements the
[historical Windows procedure](KEYCLOAK_SAML_ACCEPTANCE.md); it does not replace
that driver or its recorded evidence. A runnable procedure is not itself a
passing result: inspect the exact commit's JSON report and CI run before acceptance.

The [2026-10-15 checkpoint](evidence/SAML_LINUX_2026-10-15.md) retains successful
SQLite/PostgreSQL results, exact source/binary hashes and earlier failed attempts.

## Reproduce

Use an isolated Linux x86_64 host with Docker, Rust, Python 3, `libnss3-tools`
and Playwright's Chromium system dependencies. From the repository root:

```sh
python3 -m venv /tmp/soup-saml-driver
. /tmp/soup-saml-driver/bin/activate
python -m pip install requests==2.34.2 cryptography==50.0.2 psutil==7.2.2 playwright==1.63.0
python -m playwright install --with-deps chromium
bash scripts/keycloak-saml-linux.sh sqlite
bash scripts/keycloak-saml-linux.sh postgres
```

Each command builds the Gateway and SAML bootstrap helper, creates fresh local
services and prints named outcomes. Set `SAML_EVIDENCE_DIR` to an existing parent
location if reports should live outside `target/saml-evidence`. Reports use fresh
filenames and refuse to overwrite existing files. The
[workflow](../../.github/workflows/keycloak-saml.yml) runs both backends and retains
only sanitized JSON, including failures.

The official Keycloak 26.8.0 and PostgreSQL 16 images are pinned by digest in the
shared runtime helper. No operator realm, database URL, credentials or trust
store is accepted. PostgreSQL uses the existing owned OIDC fixture helper's
environment names solely for disposable storage; the authentication flow here
is SAML. PostgreSQL uses production migrations and verified TLS. The bootstrap
refuses existing SQLite files and populated fixture databases. Legacy Windows
bootstrap arguments retain their two-Owner behavior; `--lifecycle` provisions
an Owner, an Analyst and a separate workspace with neither membership.

## Evidence and boundaries

Keycloak generates and signs metadata and plaintext assertions. The service
provider signs its requests. The Gateway uses the locked `saml-rs` AWS-LC
provider, without FIPS or XML decryption. No positive response is signed by the
test driver. A pre-provisioned Analyst remains restricted even when the signed
IdP assertion includes an Owner role. Unknown subjects and subjects without
membership in the selected workspace cannot obtain local sessions.

The start handler sets `__Host-llm-fw-saml-flow`: Secure, HttpOnly, host-only,
ten-minute lifetime and `SameSite=None`, required for a cross-site POST. Its
digest binds RelayState to the initiating browser; it grants no authority.
Missing, duplicate or mismatched cookies are refused before pending state is
consumed. Starting another login in the same browser replaces this correlation
cookie; complete or restart the latest flow. Session cookies retain their
existing `SameSite=Lax` and CSRF requirements.

The driver checks genuine browser login, role-protected API access, session
rotation, local logout, Gateway/PostgreSQL restart, membership and credential
revocation, callback replay and request mismatch. NameID tampering targets a
second already authorized principal, avoiding an unknown-user explanation.
The missing-cookie negative is followed by acceptance of the exact same
assertion with its original cookie. Expiry uses a genuine short-lived vendor
assertion and elapsed time, without changing signed bytes or the host clock.

Both HTTPS services are loopback-only. Chromium trusts the ephemeral CA in an
isolated HOME/NSS profile; the Python client verifies an explicit CA file.
Keycloak uses `localhost` and the Gateway uses `127.0.0.1`, so the browser
actually crosses sites on the SAML POST rather than merely changing ports.
Hostname/CA failures must reject. Browser routes and HTTP calls are restricted
to the two owned origins, with automatic HTTP redirects disabled. No OS trust
modification or TLS-verification bypass is used.

## Signing certificate rotation and recovery

The fixture's private realm administrator asks Keycloak to generate a new RSA
key and disables its previous RSA signing provider. This follows Keycloak's
[component API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
and [key-provider administration](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/admin-cli.adoc).
The new assertion must fail against the old pinned metadata. An explicit
operator update replaces both metadata and its signing-certificate pin; fresh
login must then succeed and an unused retired-key assertion must fail.

For a deployment, obtain new metadata and its certificate through an authenticated
operator channel, verify the intended issuer/endpoints and certificate out of
band, then update the organization's SAML connection through the existing
protected administration route. Never trust a certificate merely because an
incoming assertion carries it. This implementation demonstrates single-pin
replacement, not automatic discovery or overlapping rollover. Recover from a
mistaken update by restoring a reviewed valid metadata/pin pair, then begin a
fresh login; do not disable signature or browser-binding checks.

Console logout revokes the local Gateway session. Vendor-wide SAML SLO is not
implemented or claimed; the Keycloak SSO session may remain active. Encrypted
assertions remain unsupported and rejected. This local fixture does not certify
customer deployment, MFA, external federation or production recovery.

Private keys, raw assertions, passwords, tokens, cookies, database rows and
runtime logs stay inside owned disposable resources. Teardown removes only
resources created by that run. Success is published only after cleanup; failure
reports retain phase, exception type, locations and completed check outcomes,
without secret exception messages. Investigate failures in an isolated run;
never upload its private working directory. Source, binary, configuration,
metadata and certificate hashes identify the exact exercised artifacts.
