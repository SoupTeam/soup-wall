// SPDX-License-Identifier: Apache-2.0

//! Operator mutation facts. Success is written by the mutation transaction;
//! refused requests are separately recorded without a request body or raw URL.

use super::{
    agent_enrollment::valid_id, now_unix, ManagedDeployment, ManagedGroupRollout,
    PostgresTenantStore, TenantStore,
};
use anyhow::{ensure, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) fn canonical_scope(value: &str) -> bool {
    valid_id(value)
}

pub(super) const SCHEMA_VERSION: i64 = 31;

pub(super) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS operator_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    received_at_unix INTEGER NOT NULL,
    actor_kind TEXT NOT NULL CHECK(actor_kind IN ('admin', 'workspace_principal', 'unavailable')),
    actor_id TEXT,
    operation TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    source_ref TEXT,
    source_sha256 TEXT,
    source_sequence INTEGER,
    outcome TEXT NOT NULL CHECK(outcome IN ('committed', 'denied', 'failed')),
    CHECK((actor_kind = 'unavailable') = (actor_id IS NULL))
);
CREATE INDEX IF NOT EXISTS operator_audit_tenant_recent ON operator_audit_events(tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS operator_audit_retention ON operator_audit_events(tenant_id, outcome, id DESC);";

pub(super) const POSTGRES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS operator_audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    received_at_unix BIGINT NOT NULL,
    actor_kind TEXT NOT NULL CHECK(actor_kind IN ('admin', 'workspace_principal', 'unavailable')),
    actor_id TEXT,
    operation TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    source_ref TEXT,
    source_sha256 TEXT,
    source_sequence BIGINT,
    outcome TEXT NOT NULL CHECK(outcome IN ('committed', 'denied', 'failed')),
    CHECK((actor_kind = 'unavailable') = (actor_id IS NULL))
);
CREATE INDEX IF NOT EXISTS operator_audit_tenant_recent ON operator_audit_events(tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS operator_audit_retention ON operator_audit_events(tenant_id, outcome, id DESC);";

macro_rules! vocabulary {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
        pub(crate) enum $name {
            $(#[serde(rename = $value)] $variant),+
        }
        impl $name {
            fn storage(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
            fn parse(value: &str) -> Result<Self> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => anyhow::bail!("unknown operator audit vocabulary"),
                }
            }
        }
    };
}

vocabulary!(AuditOperation {
    AgentEnroll => "agent.enroll",
    AgentRotate => "agent.rotate",
    AgentRevoke => "agent.revoke",
    AgentPolicyCreate => "agent_policy.create",
    AgentPolicyApprove => "agent_policy.approve",
    AgentPolicyDeploy => "agent_policy.deploy",
    AgentPolicyRollback => "agent_policy.rollback",
    GroupCreate => "group.create",
    GroupDelete => "group.delete",
    GroupAddMember => "group.add_member",
    GroupRemoveMember => "group.remove_member",
    GroupPolicyCreate => "group_policy.create",
    GroupPolicyApprove => "group_policy.approve",
    RolloutStart => "rollout.start",
    RolloutAdvance => "rollout.advance",
    RolloutPause => "rollout.pause",
    RolloutResume => "rollout.resume",
    RolloutRollback => "rollout.rollback",
    PolicyCreate => "policy.create",
    PolicyApprove => "policy.approve",
    PolicyActivate => "policy.activate",
    PolicyRollback => "policy.rollback",
    ModelPolicySet => "model_policy.set",
});

vocabulary!(AuditTarget {
    Tenant => "tenant",
    Agent => "agent",
    Group => "group",
    PolicyVersion => "policy_version",
});
vocabulary!(AuditActor {
    Admin => "admin",
    WorkspacePrincipal => "workspace_principal",
    Unavailable => "unavailable",
});
vocabulary!(AuditOutcome {
    Committed => "committed",
    Denied => "denied",
    Failed => "failed",
});

#[derive(Clone)]
pub(crate) struct OperatorContext {
    actor_kind: AuditActor,
    actor_id: Option<String>,
    received_at_unix: i64,
}

impl OperatorContext {
    pub(crate) fn admin(actor_id: Option<&str>, received_at_unix: i64) -> Self {
        Self::new(AuditActor::Admin, actor_id, received_at_unix)
    }

    pub(crate) fn workspace(actor_id: &str, received_at_unix: i64) -> Self {
        Self::new(
            AuditActor::WorkspacePrincipal,
            Some(actor_id),
            received_at_unix,
        )
    }

    pub(super) fn receipt_time(&self) -> i64 {
        self.received_at_unix
    }

    fn new(kind: AuditActor, actor_id: Option<&str>, received_at_unix: i64) -> Self {
        Self {
            actor_kind: actor_id.map_or(AuditActor::Unavailable, |_| kind),
            actor_id: actor_id.map(safe_id),
            received_at_unix,
        }
    }
}

/// A finite operation with references from committed storage or a verified
/// tenant. A deployment's numeric sequence is separate from the revision ID.
pub(super) struct AuditFact<'a> {
    operation: AuditOperation,
    target: AuditTarget,
    target_id: &'a str,
    source_ref: Option<&'a str>,
    source_sha256: Option<&'a str>,
    source_sequence: Option<u64>,
}

impl<'a> AuditFact<'a> {
    pub(super) fn deployment(value: &'a ManagedDeployment) -> Self {
        let operation = if value.action == "rollback" {
            AuditOperation::AgentPolicyRollback
        } else {
            AuditOperation::AgentPolicyDeploy
        };
        Self::new(operation, AuditTarget::Agent, &value.agent_id)
            .source(&value.revision, Some(&value.policy_sha256))
            .sequence(value.deployment_sequence)
    }

    pub(super) fn rollout(operation: AuditOperation, value: &'a ManagedGroupRollout) -> Self {
        Self::new(operation, AuditTarget::Group, &value.group_id)
            .source(&value.rollout_id, Some(&value.policy_sha256))
    }

    pub(super) fn new(operation: AuditOperation, target: AuditTarget, target_id: &'a str) -> Self {
        Self {
            operation,
            target,
            target_id,
            source_ref: None,
            source_sha256: None,
            source_sequence: None,
        }
    }

    pub(super) fn source(mut self, source: &'a str, sha256: Option<&'a str>) -> Self {
        self.source_ref = Some(source);
        self.source_sha256 = sha256;
        self
    }

    pub(super) fn sequence(mut self, sequence: u64) -> Self {
        self.source_sequence = Some(sequence);
        self
    }
}

/// Compare only persisted rollout state. A repeat Pause/Rollback or an Advance
/// that is still waiting for acknowledgements does not create a second fact.
pub(super) struct RolloutAuditState {
    rollout_id: String,
    phase: String,
    updated_at: i64,
    failure: Option<String>,
    deployments: std::collections::BTreeMap<String, u64>,
}

impl RolloutAuditState {
    pub(super) fn sqlite(tx: &Connection, tenant: &str, group: &str) -> Result<Option<Self>> {
        let row = tx.query_row(
            "SELECT rollout_id, phase, updated_at_unix, failure_reason, active_deployments_json
             FROM managed_group_rollouts WHERE tenant_id=?1 AND group_id=?2 ORDER BY rowid DESC LIMIT 1",
            params![tenant, group],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, String>(4)?)),
        ).optional()?;
        row.map(|(rollout_id, phase, updated_at, failure, active)| {
            Ok(Self {
                rollout_id,
                phase,
                updated_at,
                failure,
                deployments: serde_json::from_str(&active)?,
            })
        })
        .transpose()
    }

    pub(super) fn changed(&self, after: &ManagedGroupRollout) -> bool {
        self.rollout_id != after.rollout_id
            || self.phase != after.phase.as_str()
            || self.updated_at != after.updated_at_unix
            || self.failure != after.failure_reason
            || self.deployments != after.active_deployments
    }
}

#[derive(Serialize)]
struct AuditEvent {
    event_id: String,
    tenant_id: String,
    received_at_unix: i64,
    actor_kind: AuditActor,
    actor_id: Option<String>,
    operation: AuditOperation,
    target_kind: AuditTarget,
    target_id: String,
    source_ref: Option<String>,
    source_sha256: Option<String>,
    // Use strings for database-sized integers in browser/JSON consumers.
    source_sequence: Option<String>,
    outcome: AuditOutcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAuditQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
    #[serde(default)]
    pub download: bool,
}

impl OperatorAuditQuery {
    pub(crate) fn bounds(&self, tenant: &str) -> Result<(i64, i64)> {
        let limit = self.limit.unwrap_or(50);
        ensure!(
            valid_id(tenant) && (1..=100).contains(&limit),
            "invalid audit scope or limit"
        );
        let before = match self.before.as_deref() {
            None => i64::MAX,
            Some(value) => {
                ensure!(value.len() <= 148, "invalid audit cursor");
                let (scope, id) = value.split_once('~').context("invalid audit cursor")?;
                ensure!(scope == tenant, "invalid audit cursor scope");
                let id: i64 = id.parse().context("invalid audit cursor")?;
                ensure!(id > 0, "invalid audit cursor");
                id
            }
        };
        Ok((before, limit))
    }
}

#[derive(Serialize)]
pub(crate) struct OperatorAuditPage {
    contract_version: &'static str,
    tenant_id: String,
    observed_at_unix: i64,
    events: Vec<AuditEvent>,
    next_before: Option<String>,
}

fn page(tenant: &str, limit: i64, mut events: Vec<AuditEvent>) -> OperatorAuditPage {
    let next_before = if events.len() > limit as usize {
        events.pop();
        events
            .last()
            .map(|row| format!("{tenant}~{}", row.event_id))
    } else {
        None
    };
    OperatorAuditPage {
        contract_version: "sw-operator-audit/1",
        tenant_id: tenant.to_owned(),
        observed_at_unix: now_unix(),
        events,
        next_before,
    }
}

fn retained(outcome: AuditOutcome) -> i64 {
    match outcome {
        AuditOutcome::Committed => 10_000,
        AuditOutcome::Denied | AuditOutcome::Failed => 500,
    }
}

// IDs are finite storage identifiers. Avoid echoing a credential if someone
// deliberately used a token-shaped string as an Agent/group/revision ID.
fn safe_id(value: &str) -> String {
    if valid_id(value)
        && ![
            "sw_agent_",
            "llmfw_",
            "sw_admin_",
            "sw_live_",
            "sk-",
            "ghp_",
            "github_pat_",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        value.to_owned()
    } else {
        format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
    }
}

fn safe_digest(value: Option<&str>) -> Option<&str> {
    value.filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn sequence(fact: &AuditFact<'_>) -> Result<Option<i64>> {
    fact.source_sequence
        .map(i64::try_from)
        .transpose()
        .context("invalid audit sequence")
}

fn append_sqlite(
    tx: &Connection,
    tenant: &str,
    actor: &OperatorContext,
    fact: AuditFact<'_>,
    outcome: AuditOutcome,
) -> Result<()> {
    let inserted = tx
        .execute(
            "INSERT INTO operator_audit_events
            (tenant_id, received_at_unix, actor_kind, actor_id, operation, target_kind, target_id,
             source_ref, source_sha256, source_sequence, outcome)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                tenant,
                actor.received_at_unix,
                actor.actor_kind.storage(),
                actor.actor_id,
                fact.operation.storage(),
                fact.target.storage(),
                safe_id(fact.target_id),
                fact.source_ref.map(safe_id),
                safe_digest(fact.source_sha256),
                sequence(&fact)?,
                outcome.storage()
            ],
        )
        .context("append operator audit fact")?;
    ensure!(inserted == 1, "operator audit insert was suppressed");
    tx.execute(
        "DELETE FROM operator_audit_events WHERE tenant_id=?1 AND outcome=?2 AND id <
          (SELECT id FROM operator_audit_events WHERE tenant_id=?1 AND outcome=?2
           ORDER BY id DESC LIMIT 1 OFFSET ?3)",
        params![tenant, outcome.storage(), retained(outcome) - 1],
    )
    .context("prune operator audit retention")?;
    Ok(())
}

impl TenantStore {
    /// Only handlers with a verified operator context use this clone. A worker
    /// or an Agent acknowledgement keeps the original context-free store.
    pub(crate) fn for_operator(&self, actor: &OperatorContext) -> Self {
        let mut store = self.clone();
        store.operator = Some(actor.clone());
        if let Some(pg) = &mut store.postgres {
            pg.operator = Some(actor.clone());
        }
        store
    }

    pub(super) fn audit_committed(
        &self,
        tx: &Connection,
        tenant: &str,
        fact: AuditFact<'_>,
    ) -> Result<()> {
        if let Some(actor) = &self.operator {
            append_sqlite(tx, tenant, actor, fact, AuditOutcome::Committed)?;
        }
        Ok(())
    }

    pub(super) fn audit_workspace_committed(
        tx: &Connection,
        tenant: &str,
        principal: &str,
        received_at: i64,
        fact: AuditFact<'_>,
    ) -> Result<()> {
        append_sqlite(
            tx,
            tenant,
            &OperatorContext::workspace(principal, received_at),
            fact,
            AuditOutcome::Committed,
        )
    }

    pub(crate) async fn record_operator_attempt(
        &self,
        tenant: &str,
        actor: &OperatorContext,
        operation: AuditOperation,
        outcome: AuditOutcome,
    ) -> Result<()> {
        ensure!(
            outcome != AuditOutcome::Committed,
            "committed audit facts require a mutation transaction"
        );
        let fact = AuditFact::new(operation, AuditTarget::Tenant, tenant);
        if let Some(pg) = &self.postgres {
            let mut client = pg.checkout().await?;
            let tx = pg.bounded(client.transaction()).await?;
            pg.append_operator_audit(&tx, tenant, actor, fact, outcome)
                .await?;
            pg.bounded(tx.commit()).await?;
        } else {
            let mut conn = self.connection()?;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let exists = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
                [tenant],
                |r| r.get::<_, bool>(0),
            )?;
            if exists {
                append_sqlite(&tx, tenant, actor, fact, outcome)?;
            }
            tx.commit()?;
        }
        Ok(())
    }

    pub(crate) async fn operator_audit_page(
        &self,
        tenant: &str,
        before: i64,
        limit: i64,
    ) -> Result<OperatorAuditPage> {
        let events = if let Some(pg) = &self.postgres {
            pg.read_operator_audit(tenant, before, limit + 1).await?
        } else {
            let conn = self.connection()?;
            let mut stmt = conn.prepare(
                "SELECT id, received_at_unix, actor_kind, actor_id, operation, target_kind, target_id,
                        source_ref, source_sha256, source_sequence, outcome
                 FROM operator_audit_events WHERE tenant_id=?1 AND id<?2 ORDER BY id DESC LIMIT ?3",
            )?;
            let mut rows = stmt.query(params![tenant, before, limit + 1])?;
            let mut events = Vec::new();
            while let Some(r) = rows.next()? {
                events.push(AuditEvent {
                    event_id: r.get::<_, i64>(0)?.to_string(),
                    tenant_id: tenant.to_owned(),
                    received_at_unix: r.get(1)?,
                    actor_kind: AuditActor::parse(&r.get::<_, String>(2)?)?,
                    actor_id: r.get(3)?,
                    operation: AuditOperation::parse(&r.get::<_, String>(4)?)?,
                    target_kind: AuditTarget::parse(&r.get::<_, String>(5)?)?,
                    target_id: r.get(6)?,
                    source_ref: r.get(7)?,
                    source_sha256: r.get(8)?,
                    source_sequence: r.get::<_, Option<i64>>(9)?.map(|n| n.to_string()),
                    outcome: AuditOutcome::parse(&r.get::<_, String>(10)?)?,
                });
            }
            events
        };
        Ok(page(tenant, limit, events))
    }
}

impl PostgresTenantStore {
    pub(super) async fn operator_rollout_snapshot(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
        group: &str,
    ) -> Result<Option<RolloutAuditState>> {
        let row = self.bounded(tx.query_opt(
            "SELECT rollout_id, phase, updated_at_unix, failure_reason, active_deployments_json
             FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 ORDER BY plan_sequence DESC LIMIT 1",
            &[&tenant, &group],
        )).await?;
        row.map(|r| {
            Ok(RolloutAuditState {
                rollout_id: r.try_get(0)?,
                phase: r.try_get(1)?,
                updated_at: r.try_get(2)?,
                failure: r.try_get(3)?,
                deployments: serde_json::from_str(r.try_get(4)?)?,
            })
        })
        .transpose()
    }

    pub(super) async fn audit_committed(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
        fact: AuditFact<'_>,
    ) -> Result<()> {
        if let Some(actor) = &self.operator {
            self.append_operator_audit(tx, tenant, actor, fact, AuditOutcome::Committed)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn audit_workspace_committed(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
        principal: &str,
        received_at: i64,
        fact: AuditFact<'_>,
    ) -> Result<()> {
        self.append_operator_audit(
            tx,
            tenant,
            &OperatorContext::workspace(principal, received_at),
            fact,
            AuditOutcome::Committed,
        )
        .await
    }

    async fn append_operator_audit(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
        actor: &OperatorContext,
        fact: AuditFact<'_>,
        outcome: AuditOutcome,
    ) -> Result<()> {
        // Acquire the FK parent before the audit serialization lock, including
        // for attempts. Mutations already take their domain locks first.
        let exists = self
            .bounded(tx.query_opt(
                "SELECT id FROM tenants WHERE id=$1 FOR KEY SHARE",
                &[&tenant],
            ))
            .await?
            .is_some();
        if !exists {
            ensure!(
                outcome != AuditOutcome::Committed,
                "operator audit tenant disappeared"
            );
            return Ok(());
        }
        self.bounded(tx.query_one(
            "SELECT pg_advisory_xact_lock(734227, hashtext($1))",
            &[&tenant],
        ))
        .await?;
        let inserted = self.bounded(tx.execute(
            "INSERT INTO operator_audit_events
                (tenant_id, received_at_unix, actor_kind, actor_id, operation, target_kind, target_id,
                 source_ref, source_sha256, source_sequence, outcome)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[&tenant, &actor.received_at_unix, &actor.actor_kind.storage(), &actor.actor_id,
              &fact.operation.storage(), &fact.target.storage(), &safe_id(fact.target_id),
              &fact.source_ref.map(safe_id), &safe_digest(fact.source_sha256), &sequence(&fact)?,
              &outcome.storage()],
        )).await.context("append operator audit fact")?;
        ensure!(inserted == 1, "operator audit insert was suppressed");
        self.bounded(tx.execute(
            "DELETE FROM operator_audit_events WHERE tenant_id=$1 AND outcome=$2 AND id <
             (SELECT id FROM operator_audit_events WHERE tenant_id=$1 AND outcome=$2
              ORDER BY id DESC LIMIT 1 OFFSET $3)",
            &[&tenant, &outcome.storage(), &(retained(outcome) - 1)],
        ))
        .await
        .context("prune operator audit retention")?;
        Ok(())
    }

    async fn read_operator_audit(
        &self,
        tenant: &str,
        before: i64,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        let client = self.checkout().await?;
        let rows = self.bounded(client.query(
            "SELECT id, received_at_unix, actor_kind, actor_id, operation, target_kind, target_id,
                    source_ref, source_sha256, source_sequence, outcome
             FROM operator_audit_events WHERE tenant_id=$1 AND id<$2 ORDER BY id DESC LIMIT $3",
            &[&tenant, &before, &limit],
        )).await?;
        rows.into_iter()
            .map(|r| {
                Ok(AuditEvent {
                    event_id: r.try_get::<_, i64>(0)?.to_string(),
                    tenant_id: tenant.to_owned(),
                    received_at_unix: r.try_get(1)?,
                    actor_kind: AuditActor::parse(r.try_get(2)?)?,
                    actor_id: r.try_get(3)?,
                    operation: AuditOperation::parse(r.try_get(4)?)?,
                    target_kind: AuditTarget::parse(r.try_get(5)?)?,
                    target_id: r.try_get(6)?,
                    source_ref: r.try_get(7)?,
                    source_sha256: r.try_get(8)?,
                    source_sequence: r.try_get::<_, Option<i64>>(9)?.map(|n| n.to_string()),
                    outcome: AuditOutcome::parse(r.try_get(10)?)?,
                })
            })
            .collect()
    }
}
