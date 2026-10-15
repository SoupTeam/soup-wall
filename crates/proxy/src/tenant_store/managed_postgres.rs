// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL managed Agent storage. The enrollment row serializes deployment,
//! delivery, acknowledgement and revocation for one tenant/Agent audience.
use super::PostgresTenantStore;
use crate::tenant_store::{
    agent_enrollment::{credential_hash, valid_id},
    managed_policy::{exact_id, hex, MAX_YAML},
    now_unix, random_base64url, AppliedReport, EnrolledAgent, IssuedAgentCredential,
    ManagedAgentGroup, ManagedDeployment, ManagedGroupMember, ManagedGroupRevision,
    ManagedGroupRollout, ManagedIssuer, ManagedRevision, RolloutPhase, SignedManagedBundle,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use soup_wall_agent::AgentPolicySet;
use tokio_postgres::{Row, Transaction};

fn enrollment(row: Row) -> EnrolledAgent {
    EnrolledAgent {
        tenant_id: row.get(0),
        agent_id: row.get(1),
        created_at_unix: row.get(2),
        revoked_at_unix: row.get(3),
    }
}
fn deployment(row: Row) -> Result<ManagedDeployment> {
    Ok(ManagedDeployment {
        tenant_id: row.get(0),
        agent_id: row.get(1),
        deployment_sequence: u64::try_from(row.get::<_, i64>(2))?,
        revision: row.get(3),
        policy_sha256: row.get(4),
        action: row.get(5),
        status: row.get(6),
        issued_at_unix: row.get(7),
        applied_at_unix: row.get(8),
    })
}

impl PostgresTenantStore {
    pub(super) async fn migrate_managed_agents(&self) -> Result<()> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        // Serialize this additive migration, including simultaneous migrators.
        self.bounded(tx.query_one("SELECT pg_advisory_xact_lock(734226)", &[]))
            .await?;
        if self
            .bounded(tx.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version=26",
                &[],
            ))
            .await?
            .is_none()
        {
            self.bounded(tx.batch_execute(
                "CREATE TABLE managed_agent_enrollments (
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    agent_id TEXT NOT NULL, token_hash BYTEA NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
                    created_at_unix BIGINT NOT NULL, revoked_at_unix BIGINT,
                    PRIMARY KEY(tenant_id,agent_id));
                 CREATE TABLE managed_agent_revisions (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, revision TEXT NOT NULL,
                    policy_yaml TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
                    approved_at_unix BIGINT,
                    PRIMARY KEY(tenant_id,agent_id,revision),
                    FOREIGN KEY(tenant_id,agent_id) REFERENCES managed_agent_enrollments(tenant_id,agent_id));
                 CREATE TABLE managed_agent_deployments (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    deployment_sequence BIGINT NOT NULL CHECK(deployment_sequence>0),
                    revision TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('activate','rollback')),
                    bundle_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('issued','delivered','applied','rejected')),
                    issued_at_unix BIGINT NOT NULL, applied_at_unix BIGINT,
                    PRIMARY KEY(tenant_id,agent_id,deployment_sequence),
                    FOREIGN KEY(tenant_id,agent_id,revision) REFERENCES managed_agent_revisions(tenant_id,agent_id,revision));"
            )).await?;
            self.bounded(tx.execute(
                "INSERT INTO llm_firewall_schema_migrations(version,applied_at_unix) VALUES(26,$1)",
                &[&now_unix()],
            ))
            .await?;
        }
        if self
            .bounded(tx.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version=27",
                &[],
            ))
            .await?
            .is_none()
        {
            self.bounded(tx.batch_execute(
                "CREATE TABLE managed_agent_groups (
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    group_id TEXT NOT NULL, name TEXT NOT NULL,
                    created_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(tenant_id, group_id));
                 CREATE TABLE managed_agent_group_members (
                    tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    is_pilot BOOLEAN NOT NULL DEFAULT FALSE,
                    joined_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(tenant_id, group_id, agent_id),
                    FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE,
                    FOREIGN KEY(tenant_id, agent_id) REFERENCES managed_agent_enrollments(tenant_id, agent_id) ON DELETE CASCADE);
                 CREATE TABLE managed_group_revisions (
                    tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, revision TEXT NOT NULL,
                    policy_yaml TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
                    approved_at_unix BIGINT,
                    PRIMARY KEY(tenant_id, group_id, revision),
                    FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE);
                 CREATE TABLE managed_group_rollouts (
                    tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, rollout_id TEXT NOT NULL,
                    revision TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
                    issuer_key_id TEXT,
                    phase TEXT NOT NULL CHECK(phase IN ('pilot','standard','paused','rolling_back','completed','rolled_back','failed')),
                    pilot_agents_json TEXT NOT NULL,
                    standard_agents_json TEXT NOT NULL,
                    active_deployments_json TEXT NOT NULL,
                    previous_revisions_json TEXT NOT NULL,
                    failure_reason TEXT,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(tenant_id, group_id, rollout_id),
                    FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE);"
            )).await?;
            self.bounded(tx.execute(
                "INSERT INTO llm_firewall_schema_migrations(version,applied_at_unix) VALUES(27,$1)",
                &[&now_unix()],
            ))
            .await?;
        }
        self.bounded(tx.commit()).await?;
        Ok(())
    }

    async fn lock_managed_tenant(&self, tx: &Transaction<'_>, tenant: &str) -> Result<()> {
        ensure!(valid_id(tenant), "invalid tenant identity");
        ensure!(
            self.bounded(tx.query_opt(
                "SELECT id FROM tenants WHERE id=$1 AND active=TRUE FOR SHARE",
                &[&tenant]
            ))
            .await?
            .is_some(),
            "tenant not found or inactive"
        );
        Ok(())
    }
    async fn lock_managed_agent(
        &self,
        tx: &Transaction<'_>,
        tenant: &str,
        agent: &str,
    ) -> Result<()> {
        ensure!(valid_id(agent), "invalid Agent identity");
        self.lock_managed_tenant(tx, tenant).await?;
        ensure!(self.bounded(tx.query_opt("SELECT agent_id FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at_unix IS NULL FOR UPDATE", &[&tenant, &agent])).await?.is_some(), "Agent not enrolled or revoked");
        Ok(())
    }
    pub(in crate::tenant_store) async fn enroll_managed_agent(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<IssuedAgentCredential> {
        ensure!(valid_id(agent), "invalid Agent identity");
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_tenant(&tx, tenant).await?;
        let token = format!("sw_agent_{}", random_base64url(32));
        let hash = credential_hash(&token).context("invalid generated Agent credential")?;
        let row = self.bounded(tx.query_one("INSERT INTO managed_agent_enrollments(tenant_id,agent_id,token_hash,created_at_unix) VALUES($1,$2,$3,$4) RETURNING tenant_id,agent_id,created_at_unix,revoked_at_unix", &[&tenant,&agent,&hash,&now_unix()])).await?;
        self.bounded(tx.commit()).await?;
        Ok(IssuedAgentCredential {
            agent: enrollment(row),
            token,
        })
    }
    pub(in crate::tenant_store) async fn authenticate_managed_agent(
        &self,
        authorization: Option<&str>,
    ) -> Result<Option<EnrolledAgent>> {
        let Some(hash) = authorization
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(credential_hash)
        else {
            return Ok(None);
        };
        let client = self.checkout().await?;
        Ok(self.bounded(client.query_opt("SELECT a.tenant_id,a.agent_id,a.created_at_unix,a.revoked_at_unix FROM managed_agent_enrollments a JOIN tenants t ON t.id=a.tenant_id WHERE a.token_hash=$1 AND a.revoked_at_unix IS NULL AND t.active=TRUE", &[&hash])).await?.map(enrollment))
    }
    pub(in crate::tenant_store) async fn revoke_managed_agent(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<bool> {
        ensure!(valid_id(tenant) && valid_id(agent), "invalid identity");
        let client = self.checkout().await?;
        Ok(self.bounded(client.execute("UPDATE managed_agent_enrollments SET revoked_at_unix=$3 WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at_unix IS NULL", &[&tenant,&agent,&now_unix()])).await? == 1)
    }
    pub(in crate::tenant_store) async fn list_managed_agents(
        &self,
        tenant: &str,
    ) -> Result<Vec<EnrolledAgent>> {
        ensure!(valid_id(tenant), "invalid tenant identity");
        let client = self.checkout().await?;
        Ok(self.bounded(client.query("SELECT tenant_id,agent_id,created_at_unix,revoked_at_unix FROM managed_agent_enrollments WHERE tenant_id=$1 ORDER BY agent_id LIMIT 256", &[&tenant])).await?.into_iter().map(enrollment).collect())
    }
    pub(in crate::tenant_store) async fn create_managed_revision(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
        yaml: &str,
    ) -> Result<ManagedRevision> {
        ensure!(exact_id(revision), "invalid immutable revision");
        ensure!(
            !yaml.is_empty() && yaml.len() <= MAX_YAML,
            "Agent policy size out of bounds"
        );
        AgentPolicySet::from_yaml(yaml).context("invalid AgentPolicySet YAML")?;
        let digest = hex(&Sha256::digest(yaml.as_bytes()));
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        self.bounded(tx.execute("INSERT INTO managed_agent_revisions(tenant_id,agent_id,revision,policy_yaml,policy_sha256) VALUES($1,$2,$3,$4,$5)", &[&tenant,&agent,&revision,&yaml,&digest])).await?;
        self.bounded(tx.commit()).await?;
        Ok(ManagedRevision {
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            revision: revision.into(),
            policy_sha256: digest,
            approved: false,
        })
    }
    pub(in crate::tenant_store) async fn approve_managed_revision(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
    ) -> Result<bool> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        let changed = self.bounded(tx.execute("UPDATE managed_agent_revisions SET approved_at_unix=$4 WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3 AND approved_at_unix IS NULL", &[&tenant,&agent,&revision,&now_unix()])).await?;
        self.bounded(tx.commit()).await?;
        Ok(changed == 1)
    }
    pub(in crate::tenant_store) async fn deploy_managed_revision(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
        rollback: bool,
        issuer: &ManagedIssuer,
    ) -> Result<ManagedDeployment> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        let payload = self.bounded(tx.query_opt("SELECT policy_yaml,policy_sha256 FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3 AND approved_at_unix IS NOT NULL", &[&tenant,&agent,&revision])).await?.context("revision not approved or not found")?;
        let last = self.bounded(tx.query_opt("SELECT deployment_sequence,revision FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 ORDER BY deployment_sequence DESC LIMIT 1", &[&tenant,&agent])).await?;
        if rollback {
            let previous = last
                .as_ref()
                .context("cannot rollback with no prior deployment")?;
            ensure!(
                previous.get::<_, String>(1) != revision,
                "rollback must select a different approved revision"
            );
        }
        let seq = last
            .map(|r| r.get::<_, i64>(0))
            .unwrap_or(0)
            .checked_add(1)
            .context("sequence exhausted")?;
        let issued = now_unix();
        let mut bundle = SignedManagedBundle {
            schema_version: 1,
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            revision: revision.into(),
            deployment_sequence: seq.try_into()?,
            issued_at_unix: issued,
            expires_at_unix: issued + 3600,
            issuer_key_id: issuer.key_id.clone(),
            policy_yaml: payload.get(0),
            policy_sha256: payload.get(1),
            signature_hex: String::new(),
        };
        issuer.sign(&mut bundle)?;
        let action = if rollback { "rollback" } else { "activate" };
        let row = self.bounded(tx.query_one("INSERT INTO managed_agent_deployments(tenant_id,agent_id,deployment_sequence,revision,policy_sha256,action,bundle_json,status,issued_at_unix) VALUES($1,$2,$3,$4,$5,$6,$7,'issued',$8) RETURNING tenant_id,agent_id,deployment_sequence,revision,policy_sha256,action,status,issued_at_unix,applied_at_unix", &[&tenant,&agent,&seq,&revision,&bundle.policy_sha256,&action,&serde_json::to_string(&bundle)?,&issued])).await?;
        self.bounded(tx.commit()).await?;
        deployment(row)
    }
    pub(in crate::tenant_store) async fn deliver_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        let row = self.bounded(tx.query_opt("SELECT deployment_sequence,bundle_json,status FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 ORDER BY deployment_sequence DESC LIMIT 1", &[&tenant,&agent])).await?;
        let Some(row) = row else { return Ok(None) };
        let status: String = row.get(2);
        if status == "applied" || status == "rejected" {
            return Ok(None);
        }
        let bundle: SignedManagedBundle = serde_json::from_str(row.get::<_, String>(1).as_str())?;
        if now_unix() >= bundle.expires_at_unix {
            return Ok(None);
        }
        self.bounded(tx.execute("UPDATE managed_agent_deployments SET status='delivered' WHERE tenant_id=$1 AND agent_id=$2 AND deployment_sequence=$3 AND status='issued'", &[&tenant,&agent,&row.get::<_,i64>(0)])).await?;
        self.bounded(tx.commit()).await?;
        Ok(Some(bundle))
    }
    pub(in crate::tenant_store) async fn acknowledge_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        report: &AppliedReport,
    ) -> Result<bool> {
        ensure!(
            report.status == "applied" || report.status == "rejected",
            "invalid acknowledgement"
        );
        let seq: i64 = report.deployment_sequence.try_into()?;
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        let row = self.bounded(tx.query_opt("SELECT deployment_sequence,revision,policy_sha256,status FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 ORDER BY deployment_sequence DESC LIMIT 1", &[&tenant,&agent])).await?;
        let Some(row) = row else { return Ok(false) };
        if row.get::<_, i64>(0) != seq
            || row.get::<_, String>(1) != report.revision
            || row.get::<_, String>(2) != report.policy_sha256
        {
            return Ok(false);
        }
        let current: String = row.get(3);
        if current == "applied" || current == "rejected" {
            return Ok(current == report.status);
        }
        let applied = (report.status == "applied").then(now_unix);
        self.bounded(tx.execute("UPDATE managed_agent_deployments SET status=$4,applied_at_unix=$5 WHERE tenant_id=$1 AND agent_id=$2 AND deployment_sequence=$3", &[&tenant,&agent,&seq,&report.status,&applied])).await?;
        self.bounded(tx.commit()).await?;
        Ok(true)
    }
    pub(in crate::tenant_store) async fn list_managed_deployments(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Vec<ManagedDeployment>> {
        ensure!(exact_id(tenant) && exact_id(agent), "invalid identity");
        let client = self.checkout().await?;
        self.bounded(client.query("SELECT tenant_id,agent_id,deployment_sequence,revision,policy_sha256,action,status,issued_at_unix,applied_at_unix FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 ORDER BY deployment_sequence DESC LIMIT 50", &[&tenant,&agent])).await?.into_iter().map(deployment).collect()
    }

    pub(in crate::tenant_store) async fn create_managed_group(
        &self,
        tenant: &str,
        group_id: &str,
        name: &str,
    ) -> Result<ManagedAgentGroup> {
        ensure!(
            exact_id(tenant) && exact_id(group_id),
            "invalid group identifier"
        );
        ensure!(!name.is_empty() && name.len() <= 256, "invalid group name");
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_tenant(&tx, tenant).await?;
        let now = now_unix();
        self.bounded(tx.execute(
            "INSERT INTO managed_agent_groups (tenant_id, group_id, name, created_at_unix) VALUES ($1,$2,$3,$4)",
            &[&tenant, &group_id, &name, &now],
        )).await.context("group already exists or cannot be created")?;
        self.bounded(tx.commit()).await?;
        Ok(ManagedAgentGroup {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            name: name.into(),
            created_at_unix: now,
        })
    }

    pub(in crate::tenant_store) async fn list_managed_groups(
        &self,
        tenant: &str,
    ) -> Result<Vec<ManagedAgentGroup>> {
        ensure!(exact_id(tenant), "invalid tenant identifier");
        let client = self.checkout().await?;
        let rows = self.bounded(client.query(
            "SELECT group_id, name, created_at_unix FROM managed_agent_groups WHERE tenant_id=$1 ORDER BY created_at_unix ASC",
            &[&tenant],
        )).await?;
        Ok(rows
            .into_iter()
            .map(|r| ManagedAgentGroup {
                tenant_id: tenant.into(),
                group_id: r.get(0),
                name: r.get(1),
                created_at_unix: r.get(2),
            })
            .collect())
    }

    pub(in crate::tenant_store) async fn get_managed_group(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ManagedAgentGroup>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let client = self.checkout().await?;
        let row = self.bounded(client.query_opt(
            "SELECT name, created_at_unix FROM managed_agent_groups WHERE tenant_id=$1 AND group_id=$2",
            &[&tenant, &group_id],
        )).await?;
        Ok(row.map(|r| ManagedAgentGroup {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            name: r.get(0),
            created_at_unix: r.get(1),
        }))
    }

    pub(in crate::tenant_store) async fn delete_managed_group(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<bool> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        let active = self.bounded(tx.query_opt(
            "SELECT 1 FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 AND phase IN ('pilot','standard')",
            &[&tenant, &group_id],
        )).await?;
        ensure!(
            active.is_none(),
            "cannot delete group with active rollout in progress"
        );
        let count = self
            .bounded(tx.execute(
                "DELETE FROM managed_agent_groups WHERE tenant_id=$1 AND group_id=$2",
                &[&tenant, &group_id],
            ))
            .await?;
        self.bounded(tx.commit()).await?;
        Ok(count > 0)
    }

    pub(in crate::tenant_store) async fn add_managed_group_member(
        &self,
        tenant: &str,
        group_id: &str,
        agent_id: &str,
        is_pilot: bool,
    ) -> Result<ManagedGroupMember> {
        ensure!(
            exact_id(tenant) && exact_id(group_id) && exact_id(agent_id),
            "invalid identifier"
        );
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent_id).await?;
        let now = now_unix();
        self.bounded(tx.execute(
            "INSERT INTO managed_agent_group_members (tenant_id, group_id, agent_id, is_pilot, joined_at_unix)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT(tenant_id, group_id, agent_id) DO UPDATE SET is_pilot=EXCLUDED.is_pilot",
            &[&tenant, &group_id, &agent_id, &is_pilot, &now],
        )).await?;
        self.bounded(tx.commit()).await?;
        Ok(ManagedGroupMember {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            agent_id: agent_id.into(),
            is_pilot,
            joined_at_unix: now,
        })
    }

    pub(in crate::tenant_store) async fn remove_managed_group_member(
        &self,
        tenant: &str,
        group_id: &str,
        agent_id: &str,
    ) -> Result<bool> {
        ensure!(
            exact_id(tenant) && exact_id(group_id) && exact_id(agent_id),
            "invalid identifier"
        );
        let client = self.checkout().await?;
        let count = self.bounded(client.execute(
            "DELETE FROM managed_agent_group_members WHERE tenant_id=$1 AND group_id=$2 AND agent_id=$3",
            &[&tenant, &group_id, &agent_id],
        )).await?;
        Ok(count > 0)
    }

    pub(in crate::tenant_store) async fn list_managed_group_members(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Vec<ManagedGroupMember>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT agent_id, is_pilot, joined_at_unix FROM managed_agent_group_members
             WHERE tenant_id=$1 AND group_id=$2 ORDER BY is_pilot DESC, joined_at_unix ASC",
                &[&tenant, &group_id],
            ))
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| ManagedGroupMember {
                tenant_id: tenant.into(),
                group_id: group_id.into(),
                agent_id: r.get(0),
                is_pilot: r.get(1),
                joined_at_unix: r.get(2),
            })
            .collect())
    }

    pub(in crate::tenant_store) async fn create_managed_group_revision(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
        yaml: &str,
    ) -> Result<ManagedGroupRevision> {
        ensure!(exact_id(revision), "invalid immutable revision");
        ensure!(
            !yaml.is_empty() && yaml.len() <= MAX_YAML,
            "Agent policy size out of bounds"
        );
        AgentPolicySet::from_yaml(yaml).context("invalid AgentPolicySet YAML")?;
        let digest = hex(&Sha256::digest(yaml.as_bytes()));
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_tenant(&tx, tenant).await?;
        self.bounded(tx.execute(
            "INSERT INTO managed_group_revisions (tenant_id, group_id, revision, policy_yaml, policy_sha256)
             VALUES ($1,$2,$3,$4,$5)",
            &[&tenant, &group_id, &revision, &yaml, &digest],
        )).await.context("group revision exists or cannot be created")?;
        self.bounded(tx.commit()).await?;
        Ok(ManagedGroupRevision {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            revision: revision.into(),
            policy_sha256: digest,
            approved: false,
        })
    }

    pub(in crate::tenant_store) async fn approve_managed_group_revision(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
    ) -> Result<bool> {
        let client = self.checkout().await?;
        let count = self
            .bounded(client.execute(
                "UPDATE managed_group_revisions SET approved_at_unix=$4
             WHERE tenant_id=$1 AND group_id=$2 AND revision=$3 AND approved_at_unix IS NULL",
                &[&tenant, &group_id, &revision, &now_unix()],
            ))
            .await?;
        Ok(count == 1)
    }

    pub(in crate::tenant_store) async fn list_managed_group_revisions(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Vec<ManagedGroupRevision>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT revision, policy_sha256, approved_at_unix FROM managed_group_revisions
             WHERE tenant_id=$1 AND group_id=$2 ORDER BY revision ASC",
                &[&tenant, &group_id],
            ))
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let approved: Option<i64> = r.get(2);
                ManagedGroupRevision {
                    tenant_id: tenant.into(),
                    group_id: group_id.into(),
                    revision: r.get(0),
                    policy_sha256: r.get(1),
                    approved: approved.is_some(),
                }
            })
            .collect())
    }

    pub(in crate::tenant_store) async fn start_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
        issuer: &ManagedIssuer,
    ) -> Result<ManagedGroupRollout> {
        let (_policy_yaml, policy_sha256, pilots, standards, prevs) = {
            let client = self.checkout().await?;
            let active = self.bounded(client.query_opt(
                "SELECT rollout_id FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 AND phase IN ('pilot','standard')",
                &[&tenant, &group_id],
            )).await?;
            ensure!(
                active.is_none(),
                "active rollout already in progress for group '{}'",
                group_id
            );

            let rev_row = self.bounded(client.query_opt(
                "SELECT policy_yaml, policy_sha256 FROM managed_group_revisions WHERE tenant_id=$1 AND group_id=$2 AND revision=$3 AND approved_at_unix IS NOT NULL",
                &[&tenant, &group_id, &revision],
            )).await?;
            let rev_row = rev_row.context("group revision not approved or not found")?;
            let policy_yaml: String = rev_row.get(0);
            let policy_sha256: String = rev_row.get(1);

            let members = self.list_managed_group_members(tenant, group_id).await?;
            ensure!(!members.is_empty(), "cannot start rollout on empty group");

            let mut pilots = Vec::new();
            let mut standards = Vec::new();
            for m in members {
                if m.is_pilot {
                    pilots.push(m.agent_id);
                } else {
                    standards.push(m.agent_id);
                }
            }
            ensure!(
                !pilots.is_empty(),
                "group has no pilot agents for staged rollout"
            );

            let mut prevs = std::collections::BTreeMap::new();
            for pilot in &pilots {
                let prev = self
                    .find_last_applied_revision_before(tenant, pilot, None)
                    .await?;
                prevs.insert(pilot.clone(), prev);
            }
            for std in &standards {
                let prev = self
                    .find_last_applied_revision_before(tenant, std, None)
                    .await?;
                prevs.insert(std.clone(), prev);
            }

            for pilot in &pilots {
                let existing_sha = self.bounded(client.query_opt(
                    "SELECT policy_sha256 FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3",
                    &[&tenant, pilot, &revision],
                )).await?;
                if let Some(r) = existing_sha {
                    let sha: String = r.get(0);
                    ensure!(
                        sha == policy_sha256,
                        "revision collision on pilot agent '{}': existing revision '{}' has different digest",
                        pilot, revision
                    );
                } else {
                    self.bounded(client.execute(
                        "INSERT INTO managed_agent_revisions (tenant_id, agent_id, revision, policy_yaml, policy_sha256, approved_at_unix)
                         VALUES ($1,$2,$3,$4,$5,$6)",
                        &[&tenant, pilot, &revision, &policy_yaml, &policy_sha256, &now_unix()],
                    )).await?;
                }
            }
            (policy_yaml, policy_sha256, pilots, standards, prevs)
        };

        let mut active_deployments = std::collections::BTreeMap::new();
        for pilot in &pilots {
            let dep = self
                .deploy_managed_revision(tenant, pilot, revision, false, issuer)
                .await?;
            active_deployments.insert(pilot.clone(), dep.deployment_sequence);
        }

        let rollout_id = format!("ro_{}", random_base64url(12));
        let now = now_unix();
        let phase = RolloutPhase::Pilot;

        let client = self.checkout().await?;
        self.bounded(client.execute(
            "INSERT INTO managed_group_rollouts
             (tenant_id, group_id, rollout_id, revision, policy_sha256, issuer_key_id, phase,
              pilot_agents_json, standard_agents_json, active_deployments_json, previous_revisions_json,
              failure_reason, created_at_unix, updated_at_unix)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$12)",
            &[
                &tenant,
                &group_id,
                &rollout_id,
                &revision,
                &policy_sha256,
                &issuer.key_id(),
                &phase.as_str(),
                &serde_json::to_string(&pilots)?,
                &serde_json::to_string(&standards)?,
                &serde_json::to_string(&active_deployments)?,
                &serde_json::to_string(&prevs)?,
                &now,
            ],
        )).await?;

        Ok(ManagedGroupRollout {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            rollout_id,
            revision: revision.into(),
            policy_sha256,
            issuer_key_id: Some(issuer.key_id().into()),
            phase,
            pilot_agents: pilots,
            standard_agents: standards,
            active_deployments,
            previous_revisions: prevs,
            failure_reason: None,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    pub(in crate::tenant_store) async fn find_last_applied_revision_before(
        &self,
        tenant: &str,
        agent: &str,
        before_seq: Option<u64>,
    ) -> Result<Option<String>> {
        let client = self.checkout().await?;
        let row = match before_seq {
            Some(seq) => {
                let s = seq as i64;
                self.bounded(client.query_opt(
                    "SELECT revision FROM managed_agent_deployments
                     WHERE tenant_id=$1 AND agent_id=$2 AND status='applied' AND deployment_sequence < $3
                     ORDER BY deployment_sequence DESC LIMIT 1",
                    &[&tenant, &agent, &s],
                )).await?
            }
            None => {
                self.bounded(client.query_opt(
                    "SELECT revision FROM managed_agent_deployments
                     WHERE tenant_id=$1 AND agent_id=$2 AND status='applied'
                     ORDER BY deployment_sequence DESC LIMIT 1",
                    &[&tenant, &agent],
                ))
                .await?
            }
        };
        Ok(row.map(|r| r.get(0)))
    }

    pub(in crate::tenant_store) async fn get_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ManagedGroupRollout>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let client = self.checkout().await?;
        let row = self.bounded(client.query_opt(
            "SELECT rollout_id, revision, policy_sha256, issuer_key_id, phase,
                    pilot_agents_json, standard_agents_json, active_deployments_json,
                    previous_revisions_json, failure_reason, created_at_unix, updated_at_unix
             FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 ORDER BY created_at_unix DESC LIMIT 1",
            &[&tenant, &group_id],
        )).await?;
        let Some(r) = row else { return Ok(None) };
        let phase_str: String = r.get(4);
        let pilot_json: String = r.get(5);
        let standard_json: String = r.get(6);
        let active_json: String = r.get(7);
        let prev_json: String = r.get(8);
        Ok(Some(ManagedGroupRollout {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            rollout_id: r.get(0),
            revision: r.get(1),
            policy_sha256: r.get(2),
            issuer_key_id: r.get(3),
            phase: phase_str.parse()?,
            pilot_agents: serde_json::from_str(&pilot_json)?,
            standard_agents: serde_json::from_str(&standard_json)?,
            active_deployments: serde_json::from_str(&active_json)?,
            previous_revisions: serde_json::from_str(&prev_json)?,
            failure_reason: r.get(9),
            created_at_unix: r.get(10),
            updated_at_unix: r.get(11),
        }))
    }

    pub(in crate::tenant_store) async fn advance_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self.get_managed_group_rollout(tenant, group_id).await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        if rollout.phase != RolloutPhase::Pilot
            && rollout.phase != RolloutPhase::Standard
            && rollout.phase != RolloutPhase::RollingBack
        {
            return Ok(Some(rollout));
        }

        let client = self.checkout().await?;
        let now = now_unix();

        match rollout.phase {
            RolloutPhase::RollingBack => {
                let mut all_applied = true;
                for (agent, seq) in &rollout.active_deployments {
                    let s = *seq as i64;
                    let st = self.bounded(client.query_opt(
                        "SELECT status FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND deployment_sequence=$3",
                        &[&tenant, agent, &s],
                    )).await?;
                    let status: Option<String> = st.map(|r| r.get(0));
                    if status.as_deref() != Some("applied") {
                        all_applied = false;
                        break;
                    }
                }
                if all_applied && !rollout.active_deployments.is_empty() {
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='rolled_back', updated_at_unix=$3 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$4",
                        &[&tenant, &group_id, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::RolledBack;
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }
                Ok(Some(rollout))
            }
            RolloutPhase::Pilot => {
                let mut any_rejected = None;
                let mut all_applied = true;
                for p in &rollout.pilot_agents {
                    let seq = match rollout.active_deployments.get(p) {
                        Some(&s) => s as i64,
                        None => {
                            all_applied = false;
                            continue;
                        }
                    };
                    let dep_row = self.bounded(client.query_opt(
                        "SELECT status, policy_sha256, issued_at_unix FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND deployment_sequence=$3",
                        &[&tenant, p, &seq],
                    )).await?;

                    if let Some(r) = dep_row {
                        let status: String = r.get(0);
                        let dep_sha: String = r.get(1);
                        let issued_at: i64 = r.get(2);
                        if status == "rejected" {
                            any_rejected = Some((
                                p.clone(),
                                format!(
                                    "pilot agent '{}' rejected candidate policy revision '{}'",
                                    p, rollout.revision
                                ),
                            ));
                            break;
                        } else if status == "applied" {
                            if dep_sha != rollout.policy_sha256 {
                                all_applied = false;
                            }
                        } else {
                            all_applied = false;
                            if now - issued_at > 300 {
                                any_rejected = Some((
                                    p.clone(),
                                    format!("pilot agent '{}' timed out awaiting policy acknowledgement (>300s)", p),
                                ));
                                break;
                            }
                        }
                    } else {
                        all_applied = false;
                    }
                }

                if let Some((_rejected_agent, reason)) = any_rejected {
                    let default_issuer = ManagedIssuer::from_environment().ok();
                    let signing_issuer = default_issuer.as_ref().unwrap_or(issuer);
                    for (agent, seq) in rollout.active_deployments.clone() {
                        let prev = self
                            .find_last_applied_revision_before(tenant, &agent, Some(seq))
                            .await?;
                        if let Some(p) = prev {
                            let dep = self
                                .deploy_managed_revision(tenant, &agent, &p, true, signing_issuer)
                                .await?;
                            rollout
                                .active_deployments
                                .insert(agent, dep.deployment_sequence);
                        }
                    }
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='rolling_back', active_deployments_json=$3, failure_reason=$4, updated_at_unix=$5 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$6",
                        &[&tenant, &group_id, &serde_json::to_string(&rollout.active_deployments)?, &reason, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::RollingBack;
                    rollout.failure_reason = Some(reason);
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }

                if all_applied {
                    if rollout.standard_agents.is_empty() {
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts SET phase='completed', updated_at_unix=$3 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$4",
                            &[&tenant, &group_id, &now, &rollout.rollout_id],
                        )).await?;
                        rollout.phase = RolloutPhase::Completed;
                        rollout.updated_at_unix = now;
                        return Ok(Some(rollout));
                    }

                    let yaml_row = self.bounded(client.query_one(
                        "SELECT policy_yaml FROM managed_group_revisions WHERE tenant_id=$1 AND group_id=$2 AND revision=$3",
                        &[&tenant, &group_id, &rollout.revision],
                    )).await?;
                    let yaml: String = yaml_row.get(0);

                    for w in &rollout.standard_agents {
                        let existing_sha = self.bounded(client.query_opt(
                            "SELECT policy_sha256 FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3",
                            &[&tenant, w, &rollout.revision],
                        )).await?;
                        if let Some(r) = existing_sha {
                            let sha: String = r.get(0);
                            ensure!(
                                sha == rollout.policy_sha256,
                                "revision collision on standard agent '{}': existing revision '{}' has different digest",
                                w, rollout.revision
                            );
                        } else {
                            self.bounded(client.execute(
                                "INSERT INTO managed_agent_revisions (tenant_id, agent_id, revision, policy_yaml, policy_sha256, approved_at_unix)
                                 VALUES ($1,$2,$3,$4,$5,$6)",
                                &[&tenant, w, &rollout.revision, &yaml, &rollout.policy_sha256, &now],
                            )).await?;
                        }
                        let dep = self
                            .deploy_managed_revision(tenant, w, &rollout.revision, false, issuer)
                            .await?;
                        rollout
                            .active_deployments
                            .insert(w.clone(), dep.deployment_sequence);
                    }

                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='standard', active_deployments_json=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                        &[&tenant, &group_id, &serde_json::to_string(&rollout.active_deployments)?, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::Standard;
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }

                Ok(Some(rollout))
            }
            RolloutPhase::Standard => {
                let mut any_rejected = None;
                let mut all_applied = true;
                for w in &rollout.standard_agents {
                    let seq = match rollout.active_deployments.get(w) {
                        Some(&s) => s as i64,
                        None => {
                            all_applied = false;
                            continue;
                        }
                    };
                    let dep_row = self.bounded(client.query_opt(
                        "SELECT status, policy_sha256, issued_at_unix FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND deployment_sequence=$3",
                        &[&tenant, w, &seq],
                    )).await?;

                    if let Some(r) = dep_row {
                        let status: String = r.get(0);
                        let dep_sha: String = r.get(1);
                        let issued_at: i64 = r.get(2);
                        if status == "rejected" {
                            any_rejected = Some((
                                w.clone(),
                                format!(
                                    "standard agent '{}' rejected candidate policy revision '{}'",
                                    w, rollout.revision
                                ),
                            ));
                            break;
                        } else if status == "applied" {
                            if dep_sha != rollout.policy_sha256 {
                                all_applied = false;
                            }
                        } else {
                            all_applied = false;
                            if now - issued_at > 300 {
                                any_rejected = Some((
                                    w.clone(),
                                    format!("standard agent '{}' timed out awaiting policy acknowledgement (>300s)", w),
                                ));
                                break;
                            }
                        }
                    } else {
                        all_applied = false;
                    }
                }

                if let Some((_rejected_agent, reason)) = any_rejected {
                    let default_issuer = ManagedIssuer::from_environment().ok();
                    let signing_issuer = default_issuer.as_ref().unwrap_or(issuer);
                    for (agent, seq) in rollout.active_deployments.clone() {
                        let prev = self
                            .find_last_applied_revision_before(tenant, &agent, Some(seq))
                            .await?;
                        if let Some(p) = prev {
                            let dep = self
                                .deploy_managed_revision(tenant, &agent, &p, true, signing_issuer)
                                .await?;
                            rollout
                                .active_deployments
                                .insert(agent, dep.deployment_sequence);
                        }
                    }
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='rolling_back', active_deployments_json=$3, failure_reason=$4, updated_at_unix=$5 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$6",
                        &[&tenant, &group_id, &serde_json::to_string(&rollout.active_deployments)?, &reason, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::RollingBack;
                    rollout.failure_reason = Some(reason);
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }

                if all_applied {
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='completed', updated_at_unix=$3 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$4",
                        &[&tenant, &group_id, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::Completed;
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }

                Ok(Some(rollout))
            }
            _ => Ok(Some(rollout)),
        }
    }

    pub(in crate::tenant_store) async fn rollback_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self.get_managed_group_rollout(tenant, group_id).await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        if rollout.phase == RolloutPhase::RolledBack {
            return Ok(Some(rollout));
        }
        if rollout.phase == RolloutPhase::RollingBack {
            return Ok(Some(rollout));
        }

        let default_issuer = ManagedIssuer::from_environment().ok();
        let signing_issuer = default_issuer.as_ref().unwrap_or(issuer);
        for (agent, seq) in rollout.active_deployments.clone() {
            let prev = self
                .find_last_applied_revision_before(tenant, &agent, Some(seq))
                .await?;
            if let Some(p) = prev {
                let dep = self
                    .deploy_managed_revision(tenant, &agent, &p, true, signing_issuer)
                    .await?;
                rollout
                    .active_deployments
                    .insert(agent, dep.deployment_sequence);
            }
        }

        let now = now_unix();
        let reason = "operator requested rollback".to_string();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "UPDATE managed_group_rollouts SET phase='rolling_back', active_deployments_json=$3, failure_reason=$4, updated_at_unix=$5 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$6",
            &[&tenant, &group_id, &serde_json::to_string(&rollout.active_deployments)?, &reason, &now, &rollout.rollout_id],
        )).await?;

        rollout.phase = RolloutPhase::RollingBack;
        rollout.failure_reason = Some(reason);
        rollout.updated_at_unix = now;
        Ok(Some(rollout))
    }

    pub(in crate::tenant_store) async fn pause_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self.get_managed_group_rollout(tenant, group_id).await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        ensure!(
            rollout.phase == RolloutPhase::Pilot || rollout.phase == RolloutPhase::Standard,
            "cannot pause rollout in phase '{}'",
            rollout.phase.as_str()
        );
        let orig_phase = rollout.phase;
        let reason = format!("paused:{}", orig_phase.as_str());
        let now = now_unix();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "UPDATE managed_group_rollouts SET phase='paused', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
            &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
        )).await?;
        rollout.phase = RolloutPhase::Paused;
        rollout.failure_reason = Some(reason);
        rollout.updated_at_unix = now;
        Ok(Some(rollout))
    }

    pub(in crate::tenant_store) async fn resume_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self.get_managed_group_rollout(tenant, group_id).await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        ensure!(
            rollout.phase == RolloutPhase::Paused,
            "cannot resume rollout in phase '{}'",
            rollout.phase.as_str()
        );
        let restored_phase = match rollout.failure_reason.as_deref() {
            Some("paused:pilot") => RolloutPhase::Pilot,
            Some("paused:standard") => RolloutPhase::Standard,
            _ => {
                if rollout
                    .active_deployments
                    .keys()
                    .any(|k| rollout.standard_agents.contains(k))
                {
                    RolloutPhase::Standard
                } else {
                    RolloutPhase::Pilot
                }
            }
        };
        let now = now_unix();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "UPDATE managed_group_rollouts SET phase=$3, failure_reason=NULL, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
            &[&tenant, &group_id, &restored_phase.as_str(), &now, &rollout.rollout_id],
        )).await?;
        rollout.phase = restored_phase;
        rollout.failure_reason = None;
        rollout.updated_at_unix = now;

        self.advance_managed_group_rollout(tenant, group_id, issuer)
            .await
    }
}
