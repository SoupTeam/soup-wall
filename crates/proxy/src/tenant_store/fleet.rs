// SPDX-License-Identifier: Apache-2.0
//! Read-only, tenant-bound fleet projection. No credentials or policy payloads.
use anyhow::{ensure, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use super::{now_unix, TenantStore};

pub const VERSION: &str = "sw-agent-fleet/1";
fn default_limit() -> u32 { 25 }
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FleetQuery {
    pub limit: u32,
    pub after: String,
    pub prefix: String,
    pub enrollment: String,
    pub delivery: String,
    pub before_sequence: Option<i64>,
}
impl Default for FleetQuery {
    fn default() -> Self { Self { limit: default_limit(), after: String::new(), prefix: String::new(), enrollment: "all".into(), delivery: "all".into(), before_sequence: None } }
}
impl FleetQuery {
    pub fn validate(&self, tenant: &str, agent: Option<&str>) -> Result<()> {
        ensure!(super::agent_enrollment::valid_id(tenant), "invalid tenant");
        ensure!(agent.is_none_or(super::agent_enrollment::valid_id), "invalid Agent");
        ensure!((1..=100).contains(&self.limit), "invalid page size");
        ensure!([&self.after, &self.prefix].iter().all(|s| s.is_empty() || super::agent_enrollment::valid_id(s)), "invalid cursor or prefix");
        ensure!(["all", "active", "revoked"].contains(&self.enrollment.as_str()), "invalid enrollment filter");
        ensure!(["all", "issued", "delivered", "applied", "rejected", "no_history"].contains(&self.delivery.as_str()), "invalid delivery filter");
        ensure!(self.before_sequence.is_none_or(|n| n > 0), "invalid sequence cursor");
        ensure!(agent.is_some() || self.before_sequence.is_none(), "sequence cursor requires Agent");
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub sequence: i64,
    pub revision: String,
    pub policy_sha256: String,
    pub action: String,
    pub recorded_state: String,
    pub issued_at_unix: i64,
    pub reported_applied_at_unix: Option<i64>,
    // Existing storage does not record these event timestamps.
    pub delivered_at_unix: Option<i64>,
    pub rejected_at_unix: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FleetAgent {
    pub tenant_id: String,
    pub agent_id: String,
    pub enrolled_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
    pub latest_issued: Option<DeploymentRecord>,
    pub last_reported_applied: Option<DeploymentRecord>,
    pub current_liveness: String,
    pub runtime_coverage: String,
    pub registry_identity: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub struct FleetPage {
    pub contract_version: String,
    pub tenant_id: String,
    pub observed_at_unix: i64,
    pub agents: Vec<FleetAgent>,
    pub next_after: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub struct FleetDetail {
    pub contract_version: String,
    pub observed_at_unix: i64,
    pub agent: FleetAgent,
    pub deployments: Vec<DeploymentRecord>,
    pub next_before_sequence: Option<i64>,
}
// Every join includes BOTH identifiers. No query selects token_hash, bundle_json,
// policy_yaml, credential generation, signing keys or filesystem paths.
pub(super) fn summary_sql(with_deployments: bool, detail: bool) -> String {
    let columns = "d.deployment_sequence,d.revision,d.policy_sha256,d.action,d.status,d.issued_at_unix,d.applied_at_unix,
                   a.deployment_sequence,a.revision,a.policy_sha256,a.action,a.status,a.issued_at_unix,a.applied_at_unix";
    let joins = "LEFT JOIN managed_agent_deployments d ON d.tenant_id=e.tenant_id AND d.agent_id=e.agent_id
        AND d.deployment_sequence=(SELECT MAX(x.deployment_sequence) FROM managed_agent_deployments x WHERE x.tenant_id=e.tenant_id AND x.agent_id=e.agent_id)
        LEFT JOIN managed_agent_deployments a ON a.tenant_id=e.tenant_id AND a.agent_id=e.agent_id
        AND a.deployment_sequence=(SELECT MAX(x.deployment_sequence) FROM managed_agent_deployments x WHERE x.tenant_id=e.tenant_id AND x.agent_id=e.agent_id AND x.status='applied' AND x.applied_at_unix IS NOT NULL)";
    let cols = if with_deployments { columns } else { "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL" };
    let join = if with_deployments { joins } else { "" };
    let filter = if detail { "e.agent_id=$2" } else { "e.agent_id COLLATE \"C\">$2 AND substr(e.agent_id,1,length($3))=$3
        AND ($4='all' OR ($4='active' AND e.revoked_at_unix IS NULL) OR ($4='revoked' AND e.revoked_at_unix IS NOT NULL))" };
    let delivery = if detail { "" } else if with_deployments { "AND ($5='all' OR d.status=$5 OR ($5='no_history' AND d.deployment_sequence IS NULL))" } else { "AND ($5='all' OR $5='no_history')" };
    let limit = if detail { "LIMIT 1" } else { "ORDER BY e.agent_id COLLATE \"C\" ASC LIMIT $6" };
    format!("SELECT e.tenant_id,e.agent_id,e.created_at_unix,e.revoked_at_unix,{cols} FROM managed_agent_enrollments e {join} WHERE e.tenant_id=$1 AND {filter} {delivery} {limit}")
}
pub(super) const HISTORY_SQL: &str = "SELECT deployment_sequence,revision,policy_sha256,action,status,issued_at_unix,applied_at_unix FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND ($3::BIGINT IS NULL OR deployment_sequence<$3) ORDER BY deployment_sequence DESC LIMIT $4";
fn sqlite_record(r: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<Option<DeploymentRecord>> {
    let Some(sequence) = r.get(i)? else { return Ok(None); };
    Ok(Some(DeploymentRecord { sequence, revision:r.get(i+1)?, policy_sha256:r.get(i+2)?, action:r.get(i+3)?, recorded_state:r.get(i+4)?, issued_at_unix:r.get(i+5)?, reported_applied_at_unix:r.get(i+6)?, delivered_at_unix:None, rejected_at_unix:None }))
}
fn sqlite_agent(r: &rusqlite::Row<'_>) -> rusqlite::Result<FleetAgent> {
    Ok(FleetAgent { tenant_id:r.get(0)?, agent_id:r.get(1)?, enrolled_at_unix:r.get(2)?, revoked_at_unix:r.get(3)?, latest_issued:sqlite_record(r,4)?, last_reported_applied:sqlite_record(r,11)?, current_liveness:"unknown".into(), runtime_coverage:"unknown".into(), registry_identity:None })
}
pub(super) fn page(tenant: &str, mut agents: Vec<FleetAgent>, limit: u32, observed: i64) -> FleetPage {
    let next_after = if agents.len() > limit as usize { agents.truncate(limit as usize); agents.last().map(|a| a.agent_id.clone()) } else { None };
    FleetPage { contract_version:VERSION.into(), tenant_id:tenant.into(), observed_at_unix:observed, agents, next_after }
}
pub(super) fn detail(agent: FleetAgent, mut deployments: Vec<DeploymentRecord>, limit:u32, observed:i64) -> FleetDetail {
    let next_before_sequence = if deployments.len() > limit as usize { deployments.truncate(limit as usize); deployments.last().map(|d| d.sequence) } else { None };
    FleetDetail { contract_version:VERSION.into(), observed_at_unix:observed, agent, deployments, next_before_sequence }
}
fn table_exists(db: &rusqlite::Connection, name:&str) -> Result<bool> {
    Ok(db.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", [name], |_| Ok(())).optional()?.is_some())
}
impl TenantStore {
    pub async fn fleet_page(&self, tenant:&str, q:FleetQuery) -> Result<Option<FleetPage>> {
        q.validate(tenant,None)?;
        if let Some(pg)=&self.postgres { return pg.fleet_page(tenant,&q).await; }
        let store=self.clone(); let tenant=tenant.to_owned();
        tokio::task::spawn_blocking(move || store.fleet_page_sqlite(&tenant,&q)).await?
    }
    pub async fn fleet_detail(&self, tenant:&str, agent:&str, q:FleetQuery) -> Result<Option<FleetDetail>> {
        q.validate(tenant,Some(agent))?;
        if let Some(pg)=&self.postgres { return pg.fleet_detail(tenant,agent,&q).await; }
        let store=self.clone(); let tenant=tenant.to_owned(); let agent=agent.to_owned();
        tokio::task::spawn_blocking(move || store.fleet_detail_sqlite(&tenant,&agent,&q)).await?
    }
    fn fleet_page_sqlite(&self, tenant:&str, q:&FleetQuery) -> Result<Option<FleetPage>> {
        let mut db=self.connection()?; let tx=db.transaction()?;
        if tx.query_row("SELECT 1 FROM tenants WHERE id=?1",[tenant], |_| Ok(())).optional()?.is_none() { return Ok(None); }
        let observed=now_unix();
        if !table_exists(&tx,"managed_agent_enrollments")? { return Ok(Some(page(tenant,vec![],q.limit,observed))); }
        let sql=summary_sql(table_exists(&tx,"managed_agent_deployments")?,false).replace("COLLATE \"C\"","COLLATE BINARY");
        let mut stmt=tx.prepare(&sql)?;
        let agents=stmt.query_map(params![tenant,q.after,q.prefix,q.enrollment,q.delivery,i64::from(q.limit)+1],sqlite_agent)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(page(tenant,agents,q.limit,observed)))
    }
    fn fleet_detail_sqlite(&self, tenant:&str, agent:&str, q:&FleetQuery) -> Result<Option<FleetDetail>> {
        let mut db=self.connection()?; let tx=db.transaction()?; let observed=now_unix();
        if !table_exists(&tx,"managed_agent_enrollments")? { return Ok(None); }
        let has_history=table_exists(&tx,"managed_agent_deployments")?;
        let a=tx.query_row(&summary_sql(has_history,true),params![tenant,agent],sqlite_agent).optional()?;
        let Some(a)=a else { return Ok(None); };
        let mut history=vec![];
        if has_history {
            let sql=HISTORY_SQL.replace("$3::BIGINT","$3"); let mut stmt=tx.prepare(&sql)?;
            history=stmt.query_map(params![tenant,agent,q.before_sequence,i64::from(q.limit)+1],|r| sqlite_record(r,0).map(Option::unwrap))?.collect::<rusqlite::Result<Vec<_>>>()?;
        }
        Ok(Some(detail(a,history,q.limit,observed)))
    }
}
