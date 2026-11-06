// SPDX-License-Identifier: Apache-2.0
//! Opt-in managed Agent heartbeat sender (`sw-agent-heartbeat/1`).
//!
//! Enabled only by `SOUP_MANAGED_AGENT_HEARTBEAT=1` together with the
//! existing managed Console configuration; it then runs as one task inside
//! `agentfw serve` over the same verified Console transport and credential.
//! Each tick builds the current observation (latest-only, nothing queued).
//! Requests are bounded by the transport timeout; failures back off up to
//! five minutes. A Console outage, refusal or lost credential changes
//! nothing about local enforcement: the heartbeat only reports.
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::handlers::Shared;
use crate::managed_credential::CredentialSource;

pub const CONTRACT: &str = "sw-agent-heartbeat/1";
const DEFAULT_INTERVAL: u64 = 30;
const MIN_INTERVAL: u64 = 5;
const MAX_INTERVAL: u64 = 60;
const MAX_BACKOFF: u64 = 300;
const MAX_RESPONSE_BYTES: usize = 4096;

/// `SOUP_MANAGED_AGENT_HEARTBEAT`: unset or `0` off, `1` on; anything else
/// refuses startup so a typo never silently disables or enables it.
pub fn requested() -> Result<bool> {
    match std::env::var("SOUP_MANAGED_AGENT_HEARTBEAT") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => bail!("SOUP_MANAGED_AGENT_HEARTBEAT must be 0 or 1"),
    }
}
fn interval() -> Result<u64> {
    match std::env::var("SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS") {
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_INTERVAL),
        Ok(raw) => {
            let value: u64 = raw
                .parse()
                .context("heartbeat interval must be whole seconds")?;
            ensure!(
                (MIN_INTERVAL..=MAX_INTERVAL).contains(&value),
                "heartbeat interval must be 5 to 60 seconds"
            );
            Ok(value)
        }
        Err(_) => bail!("heartbeat interval must be whole seconds"),
    }
}
fn instance_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub struct HeartbeatSender {
    pub(crate) console: reqwest::Url,
    pub(crate) client: reqwest::Client,
    pub(crate) credentials: CredentialSource,
    pub(crate) tenant: String,
    pub(crate) agent: String,
    pub(crate) interval: Duration,
    pub(crate) instance_id: String,
}

#[derive(Deserialize)]
struct Identity {
    tenant_id: String,
    agent_id: String,
    credential_generation: i64,
}
#[derive(Deserialize)]
struct Registered {
    contract_version: String,
    registration_id: String,
    credential_generation: i64,
}
struct Registration {
    id: String,
    generation: i64,
    next: i64,
}
#[derive(Debug, PartialEq)]
enum Sent {
    Accepted,
    /// Registration no longer valid (rotation, Console restart, superseded).
    Reregister,
    /// Credential refused.
    Unauthorized,
    /// Sent faster than the Console accepts.
    TooFrequent,
    Unavailable,
}

impl HeartbeatSender {
    pub(crate) fn new(
        console: reqwest::Url,
        client: reqwest::Client,
        credentials: CredentialSource,
        tenant: String,
        agent: String,
    ) -> Result<Self> {
        Ok(Self {
            console,
            client,
            credentials,
            tenant,
            agent,
            interval: Duration::from_secs(interval()?),
            instance_id: instance_id(),
        })
    }
    fn endpoint(&self, path: &str) -> Result<reqwest::Url> {
        self.console
            .join(path)
            .context("invalid heartbeat endpoint")
    }
    async fn bounded_json<T: serde::de::DeserializeOwned>(
        mut response: reqwest::Response,
    ) -> Result<T> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= MAX_RESPONSE_BYTES,
                "oversized heartbeat response"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Learns the current server-issued credential generation (the epoch)
    /// with the credential itself, then registers this process instance.
    async fn register(&self, token: &str) -> Result<Option<Registration>> {
        let response = self
            .client
            .get(self.endpoint("agent/v1/whoami")?)
            .bearer_auth(token)
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Ok(None);
        }
        ensure!(response.status().is_success(), "Agent identity unavailable");
        let identity: Identity = Self::bounded_json(response).await?;
        ensure!(
            identity.tenant_id == self.tenant && identity.agent_id == self.agent,
            "Console identity does not match the pinned tenant and Agent"
        );
        let response = self
            .client
            .post(self.endpoint("agent/v1/heartbeat/registrations")?)
            .bearer_auth(token)
            .json(&json!({
                "contract_version": CONTRACT,
                "tenant_id": self.tenant,
                "agent_id": self.agent,
                "credential_generation": identity.credential_generation,
                "instance_id": self.instance_id,
            }))
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Ok(None);
        }
        ensure!(
            response.status() == reqwest::StatusCode::CREATED,
            "heartbeat registration refused (HTTP {})",
            response.status()
        );
        let registered: Registered = Self::bounded_json(response).await?;
        ensure!(
            registered.contract_version == CONTRACT
                && registered.credential_generation == identity.credential_generation
                && registered.registration_id.len() == 32
                && registered
                    .registration_id
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "unexpected heartbeat registration"
        );
        Ok(Some(Registration {
            id: registered.registration_id,
            generation: registered.credential_generation,
            next: 1,
        }))
    }

    async fn send(&self, token: &str, state: &Shared, r: &mut Registration) -> Result<Sent> {
        // The loaded managed policy as the runtime holds it now; nothing queued.
        let observed = state
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("firewall mutex poisoned"))?
            .active_managed_policy()
            .map(|p| {
                json!({
                    "deployment_sequence": p.deployment_sequence,
                    "revision": p.revision,
                    "policy_sha256": p.policy_sha256,
                })
            });
        let sequence = r.next;
        // A sequence is spent even if the reply is lost; never reused.
        r.next += 1;
        let response = self
            .client
            .post(self.endpoint("agent/v1/heartbeats")?)
            .bearer_auth(token)
            .json(&json!({
                "contract_version": CONTRACT,
                "tenant_id": self.tenant,
                "agent_id": self.agent,
                "credential_generation": r.generation,
                "instance_id": self.instance_id,
                "registration_id": r.id,
                "sequence": sequence,
                "observed_policy": observed,
            }))
            .send()
            .await;
        Ok(match response.map(|r| r.status().as_u16()) {
            Ok(204) => Sent::Accepted,
            Ok(409) => Sent::Reregister,
            Ok(401 | 403) => Sent::Unauthorized,
            Ok(429) => Sent::TooFrequent,
            _ => Sent::Unavailable,
        })
    }

    pub async fn run(self, state: Shared) {
        let mut registration: Option<Registration> = None;
        let mut backoff = self.interval;
        let mut delay = Duration::ZERO;
        loop {
            tokio::time::sleep(delay).await;
            let outcome = async {
                let token = self.credentials.load().map_err(|_| Sent::Unauthorized)?;
                if registration.is_none() {
                    registration = match self.register(&token).await {
                        Ok(Some(r)) => Some(r),
                        Ok(None) => return Err(Sent::Unauthorized),
                        Err(error) => {
                            tracing::warn!(error = %error, "heartbeat registration unavailable");
                            return Err(Sent::Unavailable);
                        }
                    };
                }
                let Some(r) = registration.as_mut() else {
                    return Err(Sent::Unavailable);
                };
                self.send(&token, &state, r)
                    .await
                    .map_err(|_| Sent::Unavailable)
            }
            .await
            .unwrap_or_else(|sent| sent);
            delay = match outcome {
                Sent::Accepted => {
                    backoff = self.interval;
                    self.interval
                }
                Sent::TooFrequent => self.interval,
                Sent::Reregister => {
                    registration = None;
                    Duration::from_secs(MIN_INTERVAL)
                }
                Sent::Unauthorized | Sent::Unavailable => {
                    if outcome == Sent::Unauthorized {
                        registration = None;
                    }
                    tracing::warn!(state = ?outcome, retry_seconds = backoff.as_secs(),
                        "heartbeat not accepted; enforcement unchanged");
                    let wait = backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(MAX_BACKOFF));
                    wait
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_and_interval_are_explicit_and_bounded() {
        // Environment is process-global; keep all cases in one test.
        std::env::remove_var("SOUP_MANAGED_AGENT_HEARTBEAT");
        assert!(!requested().unwrap());
        for (value, expected) in [
            ("0", Some(false)),
            ("1", Some(true)),
            ("true", None),
            ("", None),
        ] {
            std::env::set_var("SOUP_MANAGED_AGENT_HEARTBEAT", value);
            assert_eq!(requested().ok(), expected, "{value}");
        }
        std::env::remove_var("SOUP_MANAGED_AGENT_HEARTBEAT");
        std::env::remove_var("SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS");
        assert_eq!(interval().unwrap(), 30);
        for (value, ok) in [
            ("5", true),
            ("60", true),
            ("4", false),
            ("61", false),
            ("x", false),
        ] {
            std::env::set_var("SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS", value);
            assert_eq!(interval().is_ok(), ok, "{value}");
        }
        std::env::remove_var("SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS");
        let id = instance_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, instance_id());
    }
}
