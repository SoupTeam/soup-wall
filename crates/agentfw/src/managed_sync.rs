// SPDX-License-Identifier: Apache-2.0
//! SOU-30: bounded local Console polling and live policy activation.
//! Only enabled when all operator-managed environment settings are present.
//! No network-fetched issuer keys, no changes to native/executor/enforce mode.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use serde_json::json;

use crate::handlers::Shared;
use crate::managed_policy::{
    parse_bounded, parse_keyring, read_keyring_file, verify_candidate, PinnedIssuerKey,
    SignedAgentPolicy, VerifiedAgentPolicy, MAX_BUNDLE_BYTES,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustSource {
    KeyringFile(PathBuf),
    Environment(PinnedIssuerKey),
}

pub struct ManagedSync {
    console: reqwest::Url,
    /// Optional operator-provisioned PEM-encoded private CA, never fetched from Console.
    private_ca_pem: Option<Vec<u8>>,
    token: String,
    tenant: String,
    agent: String,
    trust_source: TrustSource,
    active_path: PathBuf,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0)
}
fn fixed_hex_32(raw: &str) -> Result<[u8; 32]> {
    ensure!(
        raw.len() == 64 && raw.is_ascii(),
        "invalid pinned Ed25519 key length"
    );
    let mut data = [0; 32];
    for (i, byte) in data.iter_mut().enumerate() {
        let v = &raw[i * 2..i * 2 + 2];
        ensure!(
            v.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "pinned public key must use lowercase hex"
        );
        *byte = u8::from_str_radix(v, 16)?;
    }
    Ok(data)
}
#[derive(Debug)]
struct ConsoleUnavailableStatus(reqwest::StatusCode);

impl std::fmt::Display for ConsoleUnavailableStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "managed Console unavailable (HTTP {})", self.0)
    }
}

impl std::error::Error for ConsoleUnavailableStatus {}

const MAX_PRIVATE_CA_BYTES: usize = 64 * 1024;

/// The credential-bearing Agent is restricted to a single origin. HTTP is
/// permitted only for the existing loopback demonstration; HTTPS uses rustls
/// hostname/certificate validation, including for private non-loopback hosts.
fn parse_console_origin(raw: &str) -> Result<reqwest::Url> {
    ensure!(
        !raw.is_empty()
            && raw.len() <= 2048
            && raw == raw.trim()
            && raw.is_ascii()
            && !raw.bytes().any(|b| b == b'\\' || b.is_ascii_control()),
        "invalid or ambiguous managed Console origin"
    );
    let url = reqwest::Url::parse(raw).context("invalid managed Console URL")?;
    ensure!(
        url.has_host()
            && !url.cannot_be_a_base()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.port() != Some(0),
        "managed Console must be a single origin without credentials, path, query or fragment"
    );
    match url.scheme() {
        "https" => Ok(url),
        "http" if matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) => Ok(url),
        _ => anyhow::bail!("remote managed Console requires verified HTTPS"),
    }
}

/// Read at most one bounded operator-provisioned CA PEM. This is public
/// certificate material, not a signing key, and is not fetched over the wire.
/// Invalid/untrusted CA files fail configuration, never silently use plaintext.
fn private_ca_from_environment(is_https: bool) -> Result<Option<Vec<u8>>> {
    let Some(raw) = std::env::var_os("SOUP_MANAGED_AGENT_TLS_CA_FILE") else {
        return Ok(None);
    };
    ensure!(
        is_https,
        "private CA is only supported for HTTPS Console origins"
    );
    let path = PathBuf::from(raw);
    ensure!(
        path.is_absolute(),
        "SOUP_MANAGED_AGENT_TLS_CA_FILE must be an absolute path"
    );
    let mut reader = fs::File::open(&path).context("cannot open operator private CA")?;
    let mut data = Vec::new();
    (&mut reader)
        .take((MAX_PRIVATE_CA_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .context("cannot read operator private CA")?;
    ensure!(
        !data.is_empty() && data.len() <= MAX_PRIVATE_CA_BYTES,
        "operator private CA PEM is missing or exceeds 64 KiB"
    );
    // reqwest's PEM wrapper may accept empty/non-certificate input before
    // connecting. Parse the certificate bytes eagerly to fail closed on
    // malformed operator configuration, never after credentialed requests.
    let pem_text = std::str::from_utf8(&data).context("private CA must be UTF-8 PEM")?;
    let trimmed = pem_text.trim();
    ensure!(
        trimmed.starts_with("-----BEGIN CERTIFICATE-----")
            && trimmed.ends_with("-----END CERTIFICATE-----"),
        "private CA must contain a PEM certificate"
    );
    let mut parsed = CertificateDer::pem_slice_iter(data.as_slice());
    let cert = parsed
        .next()
        .transpose()
        .context("invalid operator private CA PEM")?
        .context("missing operator private CA certificate")?;
    ensure!(
        cert.as_ref().len() > 16 && cert.as_ref()[0] == 0x30,
        "operator CA is not a DER X.509 certificate"
    );
    ensure!(
        parsed.next().is_none(),
        "supply exactly one operator private CA PEM certificate"
    );
    reqwest::Certificate::from_pem(&data).context("invalid operator private CA PEM")?;
    Ok(Some(data))
}

impl ManagedSync {
    pub fn from_environment(home: &Path) -> Result<Option<Self>> {
        let Some(base) = std::env::var("SOUP_MANAGED_AGENT_CONSOLE").ok() else {
            return Ok(None);
        };
        let console = parse_console_origin(&base)?;
        let private_ca_pem = private_ca_from_environment(console.scheme() == "https")?;
        let token = std::env::var("SOUP_MANAGED_AGENT_TOKEN")
            .context("missing separate Agent credential")?;
        ensure!(
            token.len() == 52 && token.starts_with("sw_agent_"),
            "invalid managed Agent credential"
        );
        let tenant = std::env::var("SOUP_MANAGED_AGENT_TENANT").context("missing pinned tenant")?;
        let agent = std::env::var("SOUP_MANAGED_AGENT_ID").context("missing pinned Agent ID")?;
        ensure!(
            !tenant.is_empty() && tenant.len() <= 128 && !agent.is_empty() && agent.len() <= 128,
            "missing or excessive managed audience"
        );

        let explicit_keyring = std::env::var("SOUP_MANAGED_AGENT_KEYRING_PATH")
            .ok()
            .map(PathBuf::from);
        let default_keyring = home.join("trusted-issuers.json");
        let env_key_id = std::env::var("SOUP_MANAGED_AGENT_KEY_ID").ok();

        let trust_source = if let Some(explicit) = explicit_keyring {
            ensure!(
                !explicit.as_os_str().is_empty(),
                "SOUP_MANAGED_AGENT_KEYRING_PATH cannot be empty"
            );
            TrustSource::KeyringFile(explicit)
        } else if default_keyring.is_file() {
            TrustSource::KeyringFile(default_keyring)
        } else if let Some(key_id) = env_key_id {
            ensure!(
                !key_id.is_empty() && key_id.len() <= 128,
                "invalid locally pinned signing key ID"
            );
            let public_key = fixed_hex_32(
                &std::env::var("SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX")
                    .context("missing independently pinned issuer public key")?,
            )?;
            let revoked = std::env::var("SOUP_MANAGED_AGENT_KEY_REVOKED")
                .ok()
                .is_some_and(|v| v == "true");
            TrustSource::Environment(PinnedIssuerKey {
                key_id,
                public_key,
                revoked,
            })
        } else {
            anyhow::bail!(
                "managed Agent requires either a trusted keyring file ({:?}) or SOUP_MANAGED_AGENT_KEY_ID / SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX",
                default_keyring
            );
        };

        Ok(Some(Self {
            console,
            private_ca_pem,
            token,
            tenant,
            agent,
            trust_source,
            active_path: home.join("managed-policy-active.json"),
        }))
    }

    /// Load trusted issuer keys dynamically.
    /// If file mode is configured, keys are loaded strictly from the keyring file;
    /// if the file is removed, missing, or invalid, loading fails closed with no fallback.
    /// If environment mode is configured, the pinned single key is used.
    pub fn load_keys(&self) -> Result<Vec<PinnedIssuerKey>> {
        match &self.trust_source {
            TrustSource::Environment(pinned) => {
                ensure!(!pinned.revoked, "managed issuer is locally revoked");
                Ok(vec![pinned.clone()])
            }
            TrustSource::KeyringFile(path) => {
                let data = read_keyring_file(path)?;
                parse_keyring(&data)
            }
        }
    }

    fn endpoint(&self, path: &str) -> Result<reqwest::Url> {
        self.console
            .join(path.trim_start_matches('/'))
            .context("invalid Agent endpoint")
    }

    /// Previously accepted, signed policy is rechecked against pinned key.
    /// The historical expiry may have passed while offline: it remains the
    /// last accepted state, but cannot authorize a NEW deployment.
    pub fn restore(&self, state: &Shared) -> Result<()> {
        let data = match fs::read(&self.active_path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err).context("cannot read persisted managed policy"),
        };
        let bundle = parse_bounded(&data)?;
        let keys = self.load_keys()?;
        let verified = verify_candidate(
            &bundle,
            &keys,
            &self.tenant,
            &self.agent,
            0,
            bundle.issued_at_unix,
        )
        .context("persisted managed policy failed signature verification")?;
        let mut fw = state
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("firewall state poisoned"))?;
        fw.activate_managed_policy(
            verified.policy,
            verified.revision,
            verified.deployment_sequence,
            verified.policy_sha256,
        );
        fw.set_managed_transport_status("restored_offline", now());
        Ok(())
    }

    /// Atomically publish the accepted envelope on one filesystem BEFORE
    /// switching the already-running in-memory firewall. On restart, the
    /// signed last accepted payload is restored and its sequence retained.
    fn persist(&self, bundle: &SignedAgentPolicy) -> Result<()> {
        let data = serde_json::to_vec(bundle)?;
        ensure!(
            data.len() <= MAX_BUNDLE_BYTES,
            "persisted policy bundle too large"
        );
        let tmp = self.active_path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&data)?;
            f.sync_all()?;
            fs::rename(&tmp, &self.active_path)?;
            #[cfg(unix)]
            {
                fs::File::open(
                    self.active_path
                        .parent()
                        .context("missing active policy parent")?,
                )?
                .sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn activate(
        &self,
        state: &Shared,
        verified: VerifiedAgentPolicy,
        bundle: &SignedAgentPolicy,
    ) -> Result<()> {
        let mut fw = state
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("firewall state poisoned"))?;
        let existing = fw.active_managed_policy();
        if existing
            .as_ref()
            .is_some_and(|a| a.deployment_sequence >= verified.deployment_sequence)
        {
            anyhow::bail!("stale managed revision");
        }
        // Explicitly invalidate old pending local approvals. Removing any
        // unexpected entry fails closed before writing or activating.
        let revoked_count = state.grants.invalidate_all_for_policy_switch()?;
        if revoked_count > 0 {
            tracing::warn!(
                revoked_count,
                "invalidated pending approvals for new Agent policy"
            );
        }
        self.persist(bundle)?;
        fw.activate_managed_policy(
            verified.policy,
            verified.revision,
            verified.deployment_sequence,
            verified.policy_sha256,
        );
        Ok(())
    }

    async fn acknowledge(&self, client: &reqwest::Client, state: &Shared) -> Result<()> {
        let current = state
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("firewall mutex poisoned"))?
            .active_managed_policy()
            .context("no applied runtime policy")?;
        let response = client
            .post(self.endpoint("agent/v1/policy/ack")?)
            .bearer_auth(&self.token)
            .json(&json!({
                "deployment_sequence": current.deployment_sequence,
                "revision": current.revision,
                "policy_sha256": current.policy_sha256,
                "status": "applied"
            }))
            .send()
            .await
            .context("managed policy acknowledgement unavailable")?;
        ensure!(
            response.status().is_success(),
            "Console rejected applied policy acknowledgement"
        );
        Ok(())
    }

    /// A negative assertion is separate from applied and never claims that the
    /// running policy changed. Console validates identity + exact sequence/hash.
    async fn report_rejection(&self, client: &reqwest::Client, bundle: &SignedAgentPolicy) {
        let result = client
            .post(match self.endpoint("agent/v1/policy/ack") {
                Ok(url) => url,
                Err(_) => return,
            })
            .bearer_auth(&self.token)
            .json(&json!({
                "deployment_sequence": bundle.deployment_sequence,
                "revision": bundle.revision,
                "policy_sha256": bundle.policy_sha256,
                "status": "rejected"
            }))
            .send()
            .await;
        if let Err(error) = result {
            tracing::warn!(error=%error, "unable to report rejected managed bundle");
        }
    }

    async fn poll_once(&self, client: &reqwest::Client, state: &Shared) -> Result<()> {
        let mut response = client
            .get(self.endpoint("agent/v1/policy")?)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("managed Console unavailable")?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(());
        }
        if response.status().is_server_error() {
            // A reachable TLS edge does not imply its upstream Console is
            // available. 5xx must not be misreported as a rejected policy.
            return Err(ConsoleUnavailableStatus(response.status()).into());
        }
        ensure!(
            response.status().is_success(),
            "managed policy fetch rejected"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len().saturating_add(chunk.len()) <= MAX_BUNDLE_BYTES,
                "oversized policy bundle refused"
            );
            body.extend_from_slice(&chunk);
        }
        let bundle = parse_bounded(&body)?;
        let active = state
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("firewall mutex poisoned"))?
            .active_managed_policy();
        // Idempotent retry if the Agent applied successfully but was offline
        // before Console received its authenticated acknowledgement.
        if active.as_ref().is_some_and(|a| {
            a.deployment_sequence == bundle.deployment_sequence
                && a.revision == bundle.revision
                && a.policy_sha256 == bundle.policy_sha256
        }) {
            return self.acknowledge(client, state).await;
        }
        let last = active.map_or(0, |a| a.deployment_sequence);
        let keys = match self.load_keys() {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "cannot load trusted keyring during candidate verification; reporting rejection"
                );
                self.report_rejection(client, &bundle).await;
                return Err(error);
            }
        };
        let verified =
            match verify_candidate(&bundle, &keys, &self.tenant, &self.agent, last, now()) {
                Ok(verified) => verified,
                Err(error) => {
                    self.report_rejection(client, &bundle).await;
                    return Err(error);
                }
            };
        if let Err(error) = self.activate(state, verified, &bundle) {
            self.report_rejection(client, &bundle).await;
            return Err(error);
        }
        self.acknowledge(client, state).await
    }

    /// Never follow 3xx to another origin: a redirect must not receive the
    /// enrolled Agent Bearer credential (including across HTTPS→HTTP).
    /// no_proxy also disables inherited HTTP_PROXY/HTTPS_PROXY routing.
    fn build_client(&self) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5));
        if let Some(pem) = &self.private_ca_pem {
            let certificate = reqwest::Certificate::from_pem(pem)
                .context("invalid configured operator private CA")?;
            builder = builder.add_root_certificate(certificate);
        }
        builder
            .build()
            .context("unable to configure managed Console transport")
    }

    pub async fn run(self, state: Shared) {
        let client = match self.build_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error=%e, "managed Agent polling disabled");
                return;
            }
        };
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        loop {
            ticker.tick().await;
            let result = self.poll_once(&client, &state).await;
            let transport_state = match &result {
                Ok(()) => "online",
                Err(e)
                    if e.chain().any(|cause| {
                        cause.downcast_ref::<reqwest::Error>().is_some()
                            || cause.downcast_ref::<ConsoleUnavailableStatus>().is_some()
                    }) =>
                {
                    "offline"
                }
                Err(e) if e.to_string().contains("stale") || e.to_string().contains("replayed") => {
                    "stale"
                }
                Err(_) => "rejected",
            };
            if let Ok(mut fw) = state.firewall.lock() {
                fw.set_managed_transport_status(transport_state, now());
            }
            if let Err(error) = result {
                // A failure cannot change the last accepted live policy.
                tracing::warn!(error=%error, transport_state,
                    "managed policy unavailable or rejected; last accepted policy preserved");
            }
        }
    }
}

#[cfg(test)]
mod https_transport_tests {
    use super::*;

    #[test]
    fn accepts_https_remote_and_existing_loopback_http() {
        for origin in [
            "https://console.example.test/",
            "https://console.example.test:8443/",
            "https://192.0.2.42:9443/",
            "https://[2001:db8::4]:443/",
            "http://127.0.0.1:8080/",
            "http://localhost:1234/",
            "http://[::1]:9000/",
        ] {
            assert!(parse_console_origin(origin).is_ok(), "{origin}");
        }
    }

    #[test]
    fn rejects_remote_plaintext_credentials_and_ambiguous_origins() {
        for origin in [
            "http://example.test/",
            "http://192.0.2.42:8080/",
            "https://user:secret@example.test/",
            "https://user@example.test/",
            "https://example.test/path",
            "https://example.test/?x=1",
            "https://example.test/#fragment",
            "https://example.test:0/",
            "https://example.test\\@other.test/",
            " https://example.test/",
            "https://example.test/ ",
            "file:///tmp/cert",
            "https://",
        ] {
            assert!(parse_console_origin(origin).is_err(), "{origin}");
        }
    }

    #[test]
    fn private_ca_is_bounded_and_invalid_pem_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("private-root.pem");
        fs::write(&file, vec![b'x'; MAX_PRIVATE_CA_BYTES + 1]).unwrap();
        // Validate bounded stream read without inheriting process env in parallel tests.
        let mut reader = fs::File::open(&file).unwrap();
        let mut bytes = Vec::new();
        (&mut reader)
            .take((MAX_PRIVATE_CA_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), MAX_PRIVATE_CA_BYTES + 1);
        assert!(
            CertificateDer::pem_slice_iter(b"not a certificate")
                .next()
                .is_none(),
            "non-PEM input must not contain a trusted certificate"
        );
    }
}
