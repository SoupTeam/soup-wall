// SPDX-License-Identifier: Apache-2.0
//! Opt-in reconciliation. Discovery grants no authority: each saved identity is
//! revalidated under the existing backend transaction/tenant lease.
use crate::tenant_store::TenantStore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReconciliationConfig {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub batch_size: usize,
}
impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: 5,
            batch_size: 32,
        }
    }
}
impl ReconciliationConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=300).contains(&self.interval_seconds),
            "rollout reconciliation interval must be 1..300 seconds"
        );
        anyhow::ensure!(
            (1..=100).contains(&self.batch_size),
            "rollout reconciliation batch_size must be 1..100"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RolloutCursor {
    pub tenant_id: String,
    pub group_id: String,
    pub rollout_id: String,
}

#[derive(Clone, Default, Serialize)]
pub struct ReconciliationStatus {
    pub running: bool,
    pub last_scan_unix: Option<i64>,
    pub discovery_unavailable: bool,
    // Bounded cache, diagnostic only; persisted plans remain the authority.
    #[serde(skip)]
    pub(crate) recent: std::collections::VecDeque<(RolloutCursor, Option<&'static str>)>,
}

impl TenantStore {
    pub fn reconciliation_status(&self, tenant: &str, group: &str) -> serde_json::Value {
        let status = self
            .reconciliation
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let blocked = status.recent.iter().rev().find(|(id, _)| id.tenant_id == tenant && id.group_id == group)
            .map(|(id, blocked)| serde_json::json!({"rollout_id": id.rollout_id, "blocked": blocked.is_some(), "reason": blocked}));
        serde_json::json!({"worker": &*status, "last_observation": blocked})
    }

    /// One fair bounded page. An empty page wraps on the next tick, so a
    /// permanently blocked early plan cannot starve plans later in the order.
    pub async fn reconcile_rollout_page(
        &self,
        cursor: Option<&RolloutCursor>,
        limit: usize,
    ) -> anyhow::Result<Option<RolloutCursor>> {
        self.reconcile_page_until(cursor, None, limit, None).await
    }

    async fn reconcile_page_until(
        &self,
        cursor: Option<&RolloutCursor>,
        until: Option<&RolloutCursor>,
        limit: usize,
        stop: Option<&watch::Receiver<bool>>,
    ) -> anyhow::Result<Option<RolloutCursor>> {
        let page = self
            .discover_active_rollouts_window_async(cursor, until, limit)
            .await;
        {
            let mut status = self
                .reconciliation
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            status.last_scan_unix = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            );
            status.discovery_unavailable = page.is_err();
        }
        let page = page?;
        for id in &page {
            // Do not log storage errors: they may contain connection details.
            if stop.is_some_and(|s| *s.borrow()) {
                break;
            }
            let blocked = self.reconcile_saved_rollout_async(id).await.err().map(|e| {
                let text = e.to_string();
                if text.contains("signing issuer") || text.contains("policy issuer") {
                    "signer_unavailable"
                } else {
                    "transition_unavailable"
                }
            });
            let mut status = self
                .reconciliation
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            status.recent.retain(|(old, _)| old != id);
            status.recent.push_back((id.clone(), blocked));
            while status.recent.len() > 256 {
                status.recent.pop_front();
            }
        }
        Ok(page.last().cloned())
    }

    /// Stop between transactions, never cancel a transaction after issuance.
    /// A process crash is handled by the existing durable transactional engine.
    pub async fn run_rollout_reconciliation(
        &self,
        config: ReconciliationConfig,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        config.validate()?;
        if !config.enabled {
            return Ok(());
        }
        self.reconciliation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .running = true;
        let mut cursor = None;
        let mut ceiling = None;
        let mut timer = tokio::time::interval(Duration::from_secs(config.interval_seconds));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = timer.tick() => {}
            }
            if ceiling.is_none() {
                let result = self.active_rollout_ceiling_async().await;
                {
                    let mut status = self
                        .reconciliation
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    status.last_scan_unix = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64,
                    );
                    status.discovery_unavailable = result.is_err();
                }
                match result {
                    Ok(Some(end)) => ceiling = Some(end),
                    _ => continue,
                }
            }
            // Shutdown cannot discard an in-flight page. Error retries retain
            // the last successful cursor, rather than restarting at the front.
            if let Ok(next) = self
                .reconcile_page_until(
                    cursor.as_ref(),
                    ceiling.as_ref(),
                    config.batch_size,
                    Some(&shutdown),
                )
                .await
            {
                cursor = next;
                if cursor.is_none() {
                    ceiling = None;
                }
            }
        }
        self.reconciliation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .running = false;
        Ok(())
    }
}
