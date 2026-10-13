// SPDX-License-Identifier: Apache-2.0
//! SOU-30: bounded local Console polling and live policy activation.
//! Only enabled when all operator-managed environment settings are present.
//! No network-fetched issuer keys, no changes to native/executor/enforce mode.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use serde_json::json;

use crate::handlers::Shared;
use crate::managed_policy::{
    parse_bounded, verify_candidate, PinnedIssuerKey, SignedAgentPolicy, VerifiedAgentPolicy,
    MAX_BUNDLE_BYTES,
};

pub struct ManagedSync {
    console: reqwest::Url,
    token: String,
    tenant: String,
    agent: String,
    issuer: PinnedIssuerKey,
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
impl ManagedSync {
    pub fn from_environment(home: &Path) -> Result<Option<Self>> {
        let Some(base) = std::env::var("SOUP_MANAGED_AGENT_CONSOLE").ok() else {
            return Ok(None);
        };
        let console = reqwest::Url::parse(&base).context("invalid managed Console URL")?;
        ensure!(
            console.scheme() == "http"
                && matches!(
                    console.host_str(),
                    Some("127.0.0.1" | "localhost" | "[::1]")
                )
                && console.username().is_empty()
                && console.password().is_none()
                && console.path() == "/"
                && console.query().is_none()
                && console.fragment().is_none(),
            "managed Console must be a local loopback HTTP origin"
        );
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
        let key_id = std::env::var("SOUP_MANAGED_AGENT_KEY_ID")
            .context("missing locally pinned signing key ID")?;
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
        ensure!(!revoked, "managed issuer is locally revoked");
        Ok(Some(Self {
            console,
            token,
            tenant,
            agent,
            issuer: PinnedIssuerKey {
                key_id,
                public_key,
                revoked,
            },
            active_path: home.join("managed-policy-active.json"),
        }))
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
        let verified = verify_candidate(
            &bundle,
            std::slice::from_ref(&self.issuer),
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
        let verified = match verify_candidate(
            &bundle,
            std::slice::from_ref(&self.issuer),
            &self.tenant,
            &self.agent,
            last,
            now(),
        ) {
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

    pub async fn run(self, state: Shared) {
        let client = match reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
        {
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
                    if e.chain()
                        .any(|cause| cause.downcast_ref::<reqwest::Error>().is_some()) =>
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
