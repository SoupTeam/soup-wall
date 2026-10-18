// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL projection uses one bounded repeatable-read snapshot per page.
use super::PostgresTenantStore;
use crate::tenant_store::{
    fleet::{self, DeploymentRecord, FleetAgent, FleetDetail, FleetPage, FleetQuery},
    now_unix,
};
use anyhow::Result;
use tokio_postgres::{IsolationLevel, Row};
fn record(r: &Row, i: usize) -> Option<DeploymentRecord> {
    let sequence = r.get::<_, Option<i64>>(i)?;
    Some(DeploymentRecord {
        sequence: sequence.to_string(),
        revision: r.get(i + 1),
        policy_sha256: r.get(i + 2),
        action: r.get(i + 3),
        recorded_state: r.get(i + 4),
        issued_at_unix: r.get(i + 5),
        reported_applied_at_unix: r.get(i + 6),
        delivered_at_unix: None,
        rejected_at_unix: None,
    })
}
fn agent(r: Row) -> FleetAgent {
    FleetAgent {
        tenant_id: r.get(0),
        agent_id: r.get(1),
        enrolled_at_unix: r.get(2),
        revoked_at_unix: r.get(3),
        latest_issued: record(&r, 4),
        last_reported_applied: record(&r, 11),
        current_liveness: "unknown".into(),
        runtime_coverage: "unknown".into(),
        registry_identity: None,
    }
}
impl PostgresTenantStore {
    pub(in crate::tenant_store) async fn fleet_page(
        &self,
        tenant: &str,
        q: &FleetQuery,
    ) -> Result<Option<FleetPage>> {
        let mut client = self.checkout().await?;
        let tx = self
            .bounded(
                client
                    .build_transaction()
                    .isolation_level(IsolationLevel::RepeatableRead)
                    .read_only(true)
                    .start(),
            )
            .await?;
        if self
            .bounded(tx.query_opt("SELECT 1 FROM tenants WHERE id=$1", &[&tenant]))
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let observed = now_unix();
        let rows = self
            .bounded(tx.query(
                &fleet::summary_sql(true, false),
                &[
                    &tenant,
                    &q.after,
                    &q.prefix,
                    &q.enrollment,
                    &q.delivery,
                    &(i64::from(q.limit) + 1),
                ],
            ))
            .await?;
        let result = fleet::page(
            tenant,
            rows.into_iter().map(agent).collect(),
            q.limit,
            observed,
        );
        self.bounded(tx.commit()).await?;
        Ok(Some(result))
    }
    pub(in crate::tenant_store) async fn fleet_detail(
        &self,
        tenant: &str,
        id: &str,
        q: &FleetQuery,
    ) -> Result<Option<FleetDetail>> {
        let mut client = self.checkout().await?;
        let tx = self
            .bounded(
                client
                    .build_transaction()
                    .isolation_level(IsolationLevel::RepeatableRead)
                    .read_only(true)
                    .start(),
            )
            .await?;
        let observed = now_unix();
        let row = self
            .bounded(tx.query_opt(&fleet::summary_sql(true, true), &[&tenant, &id]))
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let rows = self
            .bounded(tx.query(
                fleet::HISTORY_SQL,
                &[&tenant, &id, &q.before_sequence, &(i64::from(q.limit) + 1)],
            ))
            .await?;
        let result = fleet::detail(
            agent(row),
            rows.iter()
                .map(|r| record(r, 0).expect("deployment sequence is non-null"))
                .collect(),
            q.limit,
            observed,
        );
        self.bounded(tx.commit()).await?;
        Ok(Some(result))
    }
}
