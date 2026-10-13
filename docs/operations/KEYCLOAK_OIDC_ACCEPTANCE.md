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

Use Linux x86_64, Docker, the native Rust build prerequisites, Python 3.10+ and
NSS `certutil` (`libnss3-tools` on Ubuntu). The Keycloak 26.8.0 Linux/amd64 image
is fixed to `quay.io/keycloak/keycloak@sha256:ad1b0f0fa4bb5eff10f7a78eaafbb6d65b25431c1f824b0710836d74373a7dfb`.
Its upstream [26.8.0 release](https://github.com/keycloak/keycloak/releases/tag/26.8.0)
and [Apache-2.0 license](https://github.com/keycloak/keycloak/blob/26.8.0/LICENSE.txt)
apply; retain the image's included JVM/base-image license notices as well.
No customer account or paid service is required.

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
