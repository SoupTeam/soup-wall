// SPDX-License-Identifier: Apache-2.0
//! Read-only cross-Agent triage projection over recorded enrollment and
//! delivery state. One bounded count and one bounded keyset page per
//! request, inside one read snapshot. No credentials, policy bodies,
//! signed bundles or host data are selected, and nothing here can change
//! rollout or credential state. Recorded acknowledgements are history,
//! never current liveness or active protection.
use super::{fleet::DeploymentRecord, now_unix, TenantStore};
use anyhow::{ensure, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const VERSION: &str = "sw-agent-fleet-triage/1";
/// At most this many Agents are counted per request; beyond it the counts
/// are marked incomplete instead of growing the query.
pub const SCAN_LIMIT: i64 = 10_000;
pub const PROBLEMS: [&str; 8] = [
    "pending",
    "rejected",
    "mismatch",
    "revoked",
    "incomplete_history",
    "no_ack",
    "stale_ack",
    "no_history",
];
const FILTERS: [&str; 11] = [
    "all",
    "attention",
    "pending",
    "rejected",
    "mismatch",
    "revoked",
    "incomplete_history",
    "no_ack",
    "stale_ack",
    "no_history",
    "no_recorded_problem",
];
const ACK_AGES: [i64; 5] = [900, 3_600, 21_600, 86_400, 604_800];

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TriageQuery {
    pub limit: u32,
    pub problem: String,
    pub sort: String,
    pub prefix: String,
    pub ack_age_seconds: i64,
    pub after: String,
    pub after_ack: Option<i64>,
}
impl Default for TriageQuery {
    fn default() -> Self {
        Self {
            limit: 25,
            problem: "attention".into(),
            sort: "agent_id".into(),
            prefix: String::new(),
            ack_age_seconds: 86_400,
            after: String::new(),
            after_ack: None,
        }
    }
}
impl TriageQuery {
    pub fn validate(&self, tenant: &str) -> Result<()> {
        let id = super::agent_enrollment::valid_id;
        ensure!(id(tenant), "invalid tenant");
        ensure!((1..=100).contains(&self.limit), "invalid page size");
        ensure!(
            FILTERS.contains(&self.problem.as_str()),
            "invalid problem filter"
        );
        ensure!(
            ["agent_id", "ack_oldest"].contains(&self.sort.as_str()),
            "invalid sort"
        );
        ensure!(
            ACK_AGES.contains(&self.ack_age_seconds),
            "invalid acknowledgement age"
        );
        ensure!(
            [&self.after, &self.prefix]
                .iter()
                .all(|s| s.is_empty() || id(s)),
            "invalid cursor or prefix"
        );
        match self.sort.as_str() {
            // The age cursor is (recorded applied time or -1, Agent ID).
            "ack_oldest" => ensure!(
                self.after_ack.is_none_or(|n| n >= -1)
                    && self.after_ack.is_some() == !self.after.is_empty(),
                "invalid acknowledgement cursor"
            ),
            _ => ensure!(self.after_ack.is_none(), "cursor does not match sort"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriageAgent {
    pub tenant_id: String,
    pub agent_id: String,
    pub enrolled_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
    pub latest_issued: Option<DeploymentRecord>,
    pub last_reported_applied: Option<DeploymentRecord>,
    /// Stored deployment records; fewer than the latest sequence means
    /// missing or expired history.
    pub deployment_records: i64,
    pub problems: Vec<String>,
    pub first_group_id: Option<String>,
    pub group_count: i64,
    pub current_liveness: String,
    pub runtime_coverage: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct TriageCounts {
    /// Agents counted in this snapshot (at most `scan_limit`).
    pub counted_agents: i64,
    pub scan_limit: i64,
    /// False when the tenant has more Agents than `scan_limit`; then counts
    /// and pages both cover only the first `scan_limit` Agents by ID.
    pub complete: bool,
    pub attention: i64,
    pub pending: i64,
    pub rejected: i64,
    pub mismatch: i64,
    pub revoked: i64,
    pub incomplete_history: i64,
    pub no_ack: i64,
    pub stale_ack: i64,
    pub no_history: i64,
    pub no_recorded_problem: i64,
    /// Counted Agents matching the selected problem filter and prefix.
    pub matching: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TriageCursor {
    pub after: String,
    pub after_ack: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriagePage {
    pub contract_version: String,
    pub tenant_id: String,
    pub observed_at_unix: i64,
    pub problem: String,
    pub sort: String,
    pub prefix: String,
    pub ack_age_seconds: i64,
    pub counts: TriageCounts,
    pub agents: Vec<TriageAgent>,
    pub next: Option<TriageCursor>,
}

#[derive(Clone, Copy)]
pub(super) enum Dialect {
    Sqlite,
    Postgres,
}
impl Dialect {
    fn collate(self) -> &'static str {
        match self {
            Dialect::Sqlite => " COLLATE BINARY",
            Dialect::Postgres => " COLLATE \"C\"",
        }
    }
    /// SQLite numbers `?N` explicitly; `$N` would be numbered by first use.
    fn finish(self, sql: String) -> String {
        match self {
            Dialect::Postgres => sql,
            Dialect::Sqlite => (1..=9)
                .rev()
                .fold(sql, |s, n| s.replace(&format!("${n}"), &format!("?{n}"))),
        }
    }
}

/// Per-Agent rows with recorded problem flags. `$1` tenant, `$2` the
/// applied time before which an acknowledgement counts as old.
fn flagged(d: Dialect, deployments: bool, groups: bool) -> String {
    let c = d.collate();
    let cols = if deployments {
        "d.deployment_sequence AS d_seq,d.revision AS d_rev,d.policy_sha256 AS d_sha,d.action AS d_act,d.status AS d_st,d.issued_at_unix AS d_iss,d.applied_at_unix AS d_app,
         a.deployment_sequence AS a_seq,a.revision AS a_rev,a.policy_sha256 AS a_sha,a.action AS a_act,a.status AS a_st,a.issued_at_unix AS a_iss,a.applied_at_unix AS a_app,
         (SELECT COUNT(*) FROM managed_agent_deployments n WHERE n.tenant_id=e.tenant_id AND n.agent_id=e.agent_id) AS records"
    } else {
        "NULL AS d_seq,NULL AS d_rev,NULL AS d_sha,NULL AS d_act,NULL AS d_st,NULL AS d_iss,NULL AS d_app,
         NULL AS a_seq,NULL AS a_rev,NULL AS a_sha,NULL AS a_act,NULL AS a_st,NULL AS a_iss,NULL AS a_app,0 AS records"
    };
    let joins = if deployments { super::fleet::JOINS } else { "" };
    let group = if groups {
        format!("(SELECT MIN(m.group_id{c}) FROM managed_agent_group_members m WHERE m.tenant_id=e.tenant_id AND m.agent_id=e.agent_id) AS group_id,
         (SELECT COUNT(*) FROM managed_agent_group_members m WHERE m.tenant_id=e.tenant_id AND m.agent_id=e.agent_id) AS group_count")
    } else {
        "NULL AS group_id,0 AS group_count".into()
    };
    format!(
        "SELECT g.*,CASE WHEN g.f_pending+g.f_rejected+g.f_mismatch+g.f_revoked+g.f_incomplete+g.f_no_ack+g.f_stale+g.f_no_history>0 THEN 1 ELSE 0 END AS f_attention FROM (
         SELECT b.*,
           CASE WHEN b.d_st IN ('issued','delivered') THEN 1 ELSE 0 END AS f_pending,
           CASE WHEN b.d_st='rejected' THEN 1 ELSE 0 END AS f_rejected,
           CASE WHEN b.a_seq IS NOT NULL AND (b.a_rev<>b.d_rev OR b.a_sha<>b.d_sha) THEN 1 ELSE 0 END AS f_mismatch,
           CASE WHEN b.revoked IS NOT NULL THEN 1 ELSE 0 END AS f_revoked,
           CASE WHEN b.d_seq IS NOT NULL AND b.records<b.d_seq THEN 1 ELSE 0 END AS f_incomplete,
           CASE WHEN b.d_seq IS NOT NULL AND b.a_seq IS NULL THEN 1 ELSE 0 END AS f_no_ack,
           CASE WHEN b.a_app IS NOT NULL AND b.a_app<$2 THEN 1 ELSE 0 END AS f_stale,
           CASE WHEN b.d_seq IS NULL THEN 1 ELSE 0 END AS f_no_history
         FROM (SELECT e.agent_id{c} AS agent_id,e.created_at_unix AS enrolled,e.revoked_at_unix AS revoked,{cols},{group}
               FROM managed_agent_enrollments e {joins} WHERE e.tenant_id=$1) b) g"
    )
}
/// `$3` problem filter, `$4` prefix.
const FILTER: &str = "($3='all' OR ($3='attention' AND f_attention=1) OR ($3='no_recorded_problem' AND f_attention=0)
  OR ($3='pending' AND f_pending=1) OR ($3='rejected' AND f_rejected=1) OR ($3='mismatch' AND f_mismatch=1)
  OR ($3='revoked' AND f_revoked=1) OR ($3='incomplete_history' AND f_incomplete=1) OR ($3='no_ack' AND f_no_ack=1)
  OR ($3='stale_ack' AND f_stale=1) OR ($3='no_history' AND f_no_history=1))
  AND substr(agent_id,1,length($4))=$4";

/// Counts over the first `$5` Agents by ID: a fixed bound, not the tenant size.
pub(super) fn count_sql(d: Dialect, deployments: bool, groups: bool) -> String {
    let flags = flagged(d, deployments, groups);
    d.finish(format!(
        "SELECT COUNT(*),COALESCE(SUM(f_attention),0),COALESCE(SUM(f_pending),0),COALESCE(SUM(f_rejected),0),
           COALESCE(SUM(f_mismatch),0),COALESCE(SUM(f_revoked),0),COALESCE(SUM(f_incomplete),0),COALESCE(SUM(f_no_ack),0),
           COALESCE(SUM(f_stale),0),COALESCE(SUM(f_no_history),0),COALESCE(SUM(CASE WHEN {FILTER} THEN 1 ELSE 0 END),0)
         FROM (SELECT * FROM ({flags}) s ORDER BY agent_id LIMIT $5) t"
    ))
}
/// `$5` cursor Agent ID, `$6` cursor applied time (age sort), `$7` limit + 1,
/// `$8` the count bound. Pages draw from the same first `$8` Agents by ID
/// as the counts, so a listed Agent is always inside the counted universe.
pub(super) fn page_sql(d: Dialect, deployments: bool, groups: bool, sort: &str) -> String {
    let flags = flagged(d, deployments, groups);
    let (cursor, order) = if sort == "ack_oldest" {
        (
            "($5='' OR COALESCE(a_app,-1)>$6 OR (COALESCE(a_app,-1)=$6 AND agent_id>$5))",
            "COALESCE(a_app,-1) ASC,agent_id ASC",
        )
    } else {
        // `$6` is -2 here, below every recorded value, so it never filters.
        ("agent_id>$5 AND COALESCE(a_app,-1)>$6", "agent_id ASC")
    };
    d.finish(format!(
        "SELECT agent_id,enrolled,revoked,d_seq,d_rev,d_sha,d_act,d_st,d_iss,d_app,a_seq,a_rev,a_sha,a_act,a_st,a_iss,a_app,
           records,group_id,group_count,f_pending,f_rejected,f_mismatch,f_revoked,f_incomplete,f_no_ack,f_stale,f_no_history
         FROM (SELECT * FROM ({flags}) u ORDER BY agent_id LIMIT $8) s WHERE {FILTER} AND {cursor} ORDER BY {order} LIMIT $7"
    ))
}
pub(super) const TOTAL_SQL: &str =
    "SELECT COUNT(*) FROM (SELECT 1 FROM managed_agent_enrollments WHERE tenant_id=$1 LIMIT $2) x";

/// One page row, independent of the driver.
pub(super) struct RawRow {
    pub agent_id: String,
    pub enrolled: i64,
    pub revoked: Option<i64>,
    pub latest: Option<DeploymentRecord>,
    pub applied: Option<DeploymentRecord>,
    pub records: i64,
    pub group_id: Option<String>,
    pub group_count: i64,
    pub flags: [bool; 8],
}
pub(super) fn assemble(
    tenant: &str,
    q: &TriageQuery,
    observed: i64,
    counts: TriageCounts,
    mut rows: Vec<RawRow>,
) -> TriagePage {
    let more = rows.len() > q.limit as usize;
    rows.truncate(q.limit as usize);
    let next = if more {
        rows.last().map(|r| TriageCursor {
            after: r.agent_id.clone(),
            after_ack: (q.sort == "ack_oldest").then(|| {
                r.applied
                    .as_ref()
                    .and_then(|a| a.reported_applied_at_unix)
                    .unwrap_or(-1)
            }),
        })
    } else {
        None
    };
    let agents = rows
        .into_iter()
        .map(|r| TriageAgent {
            tenant_id: tenant.into(),
            agent_id: r.agent_id,
            enrolled_at_unix: r.enrolled,
            revoked_at_unix: r.revoked,
            latest_issued: r.latest,
            last_reported_applied: r.applied,
            deployment_records: r.records,
            problems: PROBLEMS
                .iter()
                .zip(r.flags)
                .filter(|(_, on)| *on)
                .map(|(p, _)| (*p).to_string())
                .collect(),
            first_group_id: r.group_id,
            group_count: r.group_count,
            current_liveness: "unknown".into(),
            runtime_coverage: "unknown".into(),
        })
        .collect();
    TriagePage {
        contract_version: VERSION.into(),
        tenant_id: tenant.into(),
        observed_at_unix: observed,
        problem: q.problem.clone(),
        sort: q.sort.clone(),
        prefix: q.prefix.clone(),
        ack_age_seconds: q.ack_age_seconds,
        counts,
        agents,
        next,
    }
}
pub(super) fn counts(total: i64, v: [i64; 11]) -> TriageCounts {
    TriageCounts {
        counted_agents: v[0],
        scan_limit: SCAN_LIMIT,
        complete: total <= SCAN_LIMIT,
        attention: v[1],
        pending: v[2],
        rejected: v[3],
        mismatch: v[4],
        revoked: v[5],
        incomplete_history: v[6],
        no_ack: v[7],
        stale_ack: v[8],
        no_history: v[9],
        no_recorded_problem: v[0] - v[1],
        matching: v[10],
    }
}

fn sqlite_record(r: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<Option<DeploymentRecord>> {
    let Some(sequence) = r.get::<_, Option<i64>>(i)? else {
        return Ok(None);
    };
    Ok(Some(DeploymentRecord {
        sequence: sequence.to_string(),
        revision: r.get(i + 1)?,
        policy_sha256: r.get(i + 2)?,
        action: r.get(i + 3)?,
        recorded_state: r.get(i + 4)?,
        issued_at_unix: r.get(i + 5)?,
        reported_applied_at_unix: r.get(i + 6)?,
        delivered_at_unix: None,
        rejected_at_unix: None,
    }))
}
fn sqlite_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    let mut flags = [false; 8];
    for (i, flag) in flags.iter_mut().enumerate() {
        *flag = r.get::<_, i64>(20 + i)? == 1;
    }
    Ok(RawRow {
        agent_id: r.get(0)?,
        enrolled: r.get(1)?,
        revoked: r.get(2)?,
        latest: sqlite_record(r, 3)?,
        applied: sqlite_record(r, 10)?,
        records: r.get(17)?,
        group_id: r.get(18)?,
        group_count: r.get(19)?,
        flags,
    })
}

impl TenantStore {
    pub async fn fleet_triage(&self, tenant: &str, q: TriageQuery) -> Result<Option<TriagePage>> {
        q.validate(tenant)?;
        if let Some(pg) = &self.postgres {
            return pg.fleet_triage(tenant, &q).await;
        }
        let store = self.clone();
        let tenant = tenant.to_owned();
        tokio::task::spawn_blocking(move || store.fleet_triage_sqlite(&tenant, &q)).await?
    }
    fn fleet_triage_sqlite(&self, tenant: &str, q: &TriageQuery) -> Result<Option<TriagePage>> {
        let mut db = self.connection()?;
        // One read transaction: counts and page describe the same snapshot.
        let tx = db.transaction()?;
        if tx
            .query_row("SELECT 1 FROM tenants WHERE id=?1", [tenant], |_| Ok(()))
            .optional()?
            .is_none()
        {
            return Ok(None);
        }
        let observed = now_unix();
        let exists = |name: &str| -> Result<bool> {
            Ok(tx
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        };
        if !exists("managed_agent_enrollments")? {
            return Ok(Some(assemble(
                tenant,
                q,
                observed,
                counts(0, [0; 11]),
                vec![],
            )));
        }
        let (deployments, groups) = (
            exists("managed_agent_deployments")?,
            exists("managed_agent_group_members")?,
        );
        let stale_before = observed - q.ack_age_seconds;
        let total: i64 = tx.query_row(
            &Dialect::Sqlite.finish(TOTAL_SQL.into()),
            params![tenant, SCAN_LIMIT + 1],
            |r| r.get(0),
        )?;
        let v = tx.query_row(
            &count_sql(Dialect::Sqlite, deployments, groups),
            params![tenant, stale_before, q.problem, q.prefix, SCAN_LIMIT],
            |r| {
                let mut v = [0i64; 11];
                for (i, slot) in v.iter_mut().enumerate() {
                    *slot = r.get(i)?;
                }
                Ok(v)
            },
        )?;
        let mut stmt = tx.prepare(&page_sql(Dialect::Sqlite, deployments, groups, &q.sort))?;
        let rows = stmt
            .query_map(
                params![
                    tenant,
                    stale_before,
                    q.problem,
                    q.prefix,
                    q.after,
                    q.after_ack.unwrap_or(-2),
                    i64::from(q.limit) + 1,
                    SCAN_LIMIT
                ],
                sqlite_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(assemble(tenant, q, observed, counts(total, v), rows)))
    }
}
