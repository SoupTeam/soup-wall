// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL triage projection: counts and page in one bounded
//! repeatable-read, read-only snapshot.
use super::PostgresTenantStore;
use crate::tenant_store::{
    fleet::DeploymentRecord,
    fleet_triage::{self, Dialect, RawRow, TriagePage, TriageQuery, SCAN_LIMIT},
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
fn row(r: &Row) -> RawRow {
    let mut flags = [false; 8];
    for (i, flag) in flags.iter_mut().enumerate() {
        *flag = r.get::<_, i32>(20 + i) == 1;
    }
    RawRow {
        agent_id: r.get(0),
        enrolled: r.get(1),
        revoked: r.get(2),
        latest: record(r, 3),
        applied: record(r, 10),
        records: r.get(17),
        group_id: r.get(18),
        group_count: r.get(19),
        flags,
    }
}

impl PostgresTenantStore {
    pub(in crate::tenant_store) async fn fleet_triage(
        &self,
        tenant: &str,
        q: &TriageQuery,
    ) -> Result<Option<TriagePage>> {
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
        let stale_before = observed - q.ack_age_seconds;
        let total: i64 = self
            .bounded(tx.query_one(fleet_triage::TOTAL_SQL, &[&tenant, &(SCAN_LIMIT + 1)]))
            .await?
            .get(0);
        let count = self
            .bounded(tx.query_one(
                &fleet_triage::count_sql(Dialect::Postgres, true, true),
                &[&tenant, &stale_before, &q.problem, &q.prefix, &SCAN_LIMIT],
            ))
            .await?;
        let mut v = [0i64; 11];
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = count.get(i);
        }
        let rows = self
            .bounded(tx.query(
                &fleet_triage::page_sql(Dialect::Postgres, true, true, &q.sort),
                &[
                    &tenant,
                    &stale_before,
                    &q.problem,
                    &q.prefix,
                    &q.after,
                    &q.after_ack.unwrap_or(-2),
                    &(i64::from(q.limit) + 1),
                    &SCAN_LIMIT,
                ],
            ))
            .await?;
        let page = fleet_triage::assemble(
            tenant,
            q,
            observed,
            fleet_triage::counts(total, v),
            rows.iter().map(row).collect(),
        );
        self.bounded(tx.commit()).await?;
        Ok(Some(page))
    }
}
