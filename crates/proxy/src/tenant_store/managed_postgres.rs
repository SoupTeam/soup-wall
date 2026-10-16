// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL managed Agent storage. The enrollment row serializes deployment,
//! delivery, acknowledgement and revocation for one tenant/Agent audience.
use super::PostgresTenantStore;
use crate::tenant_store::{
    agent_enrollment::{credential_hash, valid_id, validated_rotation},
    managed_policy::{
        acknowledgement_overdue, exact_id, hex, rollout_agent_status, DeploymentMode, MAX_YAML,
    },
    now_unix, random_base64url, AppliedReport, EnrolledAgent, IssuedAgentCredential,
    ManagedAgentGroup, ManagedDeployment, ManagedGroupMember, ManagedGroupRevision,
    ManagedGroupRollout, ManagedIssuer, ManagedRevision, RolloutPhase, RotationOutcome,
    RotationRequest, SignedManagedBundle,
};
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use soup_wall_agent::AgentPolicySet;
use tokio_postgres::{GenericClient, Row, Transaction};

fn enrollment(row: Row) -> EnrolledAgent {
    EnrolledAgent {
        tenant_id: row.get(0),
        agent_id: row.get(1),
        created_at_unix: row.get(2),
        revoked_at_unix: row.get(3),
        credential_generation: row.get(4),
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
            self.ensure_group_tables(&*tx).await?;
            self.bounded(tx.batch_execute("ALTER TABLE managed_group_rollouts ADD COLUMN IF NOT EXISTS initial_sequences_json TEXT NOT NULL DEFAULT '{}';")).await?;
            let has_sequence = self.bounded(tx.query_opt("SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='managed_group_rollouts' AND column_name='plan_sequence'", &[])).await?.is_some();
            if !has_sequence {
                self.bounded(tx.batch_execute("ALTER TABLE managed_group_rollouts ADD COLUMN plan_sequence BIGSERIAL NOT NULL;")).await?;
            }
            self.bounded(tx.execute(
                "INSERT INTO llm_firewall_schema_migrations(version,applied_at_unix) VALUES(27,$1)",
                &[&now_unix()],
            ))
            .await?;
        }
        // SOU-55: explicit version 28 follows accepted group rollout version 27.
        // Advisory transaction lock above serializes simultaneous schema upgrades.
        if self
            .bounded(tx.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version=28",
                &[],
            ))
            .await?
            .is_none()
        {
            self.bounded(tx.batch_execute(
                "ALTER TABLE managed_agent_enrollments
                     ADD COLUMN IF NOT EXISTS credential_generation BIGINT NOT NULL DEFAULT 1 CHECK(credential_generation > 0);
                 ALTER TABLE managed_agent_enrollments
                     ADD COLUMN IF NOT EXISTS last_rotation_id TEXT;
                 ALTER TABLE managed_agent_enrollments
                     ADD COLUMN IF NOT EXISTS last_rotation_expected_generation BIGINT;
                 ALTER TABLE managed_agent_enrollments
                     ADD COLUMN IF NOT EXISTS last_rotation_digest BYTEA;"
            )).await?;
            self.bounded(tx.execute(
                "INSERT INTO llm_firewall_schema_migrations(version,applied_at_unix) VALUES(28,$1)",
                &[&now_unix()],
            ))
            .await?;
        }
        self.bounded(tx.commit()).await?;
        Ok(())
    }

    async fn ensure_group_tables<C: GenericClient + Sync>(&self, client: &C) -> Result<()> {
        self.bounded(client.batch_execute(
            "CREATE TABLE IF NOT EXISTS managed_agent_groups (
                tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                group_id TEXT NOT NULL, name TEXT NOT NULL,
                created_at_unix BIGINT NOT NULL,
                PRIMARY KEY(tenant_id, group_id));
             CREATE TABLE IF NOT EXISTS managed_agent_group_members (
                tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                is_pilot BOOLEAN NOT NULL DEFAULT FALSE,
                joined_at_unix BIGINT NOT NULL,
                PRIMARY KEY(tenant_id, group_id, agent_id),
                FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE,
                FOREIGN KEY(tenant_id, agent_id) REFERENCES managed_agent_enrollments(tenant_id, agent_id) ON DELETE CASCADE);
             CREATE TABLE IF NOT EXISTS managed_group_revisions (
                tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, revision TEXT NOT NULL,
                policy_yaml TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
                approved_at_unix BIGINT,
                PRIMARY KEY(tenant_id, group_id, revision),
                FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE);
             CREATE TABLE IF NOT EXISTS managed_group_rollouts (
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
                initial_sequences_json TEXT NOT NULL DEFAULT '{}',
                plan_sequence BIGSERIAL NOT NULL,
                PRIMARY KEY(tenant_id, group_id, rollout_id),
                FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE);"
        )).await?;
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
        let row = self.bounded(tx.query_one("INSERT INTO managed_agent_enrollments(tenant_id,agent_id,token_hash,created_at_unix) VALUES($1,$2,$3,$4) RETURNING tenant_id,agent_id,created_at_unix,revoked_at_unix,credential_generation", &[&tenant,&agent,&hash,&now_unix()])).await?;
        self.bounded(tx.commit()).await?;
        Ok(IssuedAgentCredential {
            agent: enrollment(row),
            token,
        })
    }
    pub(in crate::tenant_store) async fn rotate_managed_agent(
        &self,
        tenant: &str,
        agent: &str,
        input: &RotationRequest,
    ) -> Result<RotationOutcome> {
        let new_hash = validated_rotation(input)?;
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        let row = self
            .bounded(tx.query_one(
                "SELECT token_hash,credential_generation,last_rotation_id,
                    last_rotation_expected_generation,last_rotation_digest
             FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE",
                &[&tenant, &agent],
            ))
            .await?;
        let old_hash: Vec<u8> = row.get(0);
        let generation: i64 = row.get(1);
        let last_id: Option<String> = row.get(2);
        let last_generation: Option<i64> = row.get(3);
        let last_digest: Option<Vec<u8>> = row.get(4);
        if last_id.as_deref() == Some(&input.operation_id)
            && last_generation == Some(input.expected_generation)
            && last_digest.as_deref() == Some(new_hash.as_slice())
        {
            return Ok(RotationOutcome {
                tenant_id: tenant.into(),
                agent_id: agent.into(),
                generation,
                operation_id: input.operation_id.clone(),
                already_applied: true,
            });
        }
        ensure!(
            last_id.as_deref() != Some(&input.operation_id),
            "operation identifier reused with different parameters"
        );
        ensure!(
            generation == input.expected_generation,
            "stale credential generation"
        );
        ensure!(
            old_hash != new_hash,
            "replacement must differ from current credential"
        );
        let next = generation
            .checked_add(1)
            .context("credential generation exhausted")?;
        self.bounded(tx.execute(
            "UPDATE managed_agent_enrollments
             SET token_hash=$3,credential_generation=$4,last_rotation_id=$5,
                 last_rotation_expected_generation=$6,last_rotation_digest=$7
             WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at_unix IS NULL",
            &[
                &tenant,
                &agent,
                &new_hash,
                &next,
                &input.operation_id,
                &input.expected_generation,
                &new_hash,
            ],
        ))
        .await?;
        self.bounded(tx.commit()).await?;
        Ok(RotationOutcome {
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            generation: next,
            operation_id: input.operation_id.clone(),
            already_applied: false,
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
        Ok(self.bounded(client.query_opt("SELECT a.tenant_id,a.agent_id,a.created_at_unix,a.revoked_at_unix,a.credential_generation FROM managed_agent_enrollments a JOIN tenants t ON t.id=a.tenant_id WHERE a.token_hash=$1 AND a.revoked_at_unix IS NULL AND t.active=TRUE", &[&hash])).await?.map(enrollment))
    }
    pub(in crate::tenant_store) async fn revoke_managed_agent(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<bool> {
        ensure!(valid_id(tenant) && valid_id(agent), "invalid identity");
        let mut connection = self.checkout().await?;
        let client = self.bounded(connection.transaction()).await?;
        self.lock_managed_tenant(&client, tenant).await?;
        let changed = self.bounded(client.execute("UPDATE managed_agent_enrollments SET revoked_at_unix=$3 WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at_unix IS NULL", &[&tenant,&agent,&now_unix()])).await? == 1;
        self.bounded(client.commit()).await?;
        Ok(changed)
    }
    pub(in crate::tenant_store) async fn list_managed_agents(
        &self,
        tenant: &str,
    ) -> Result<Vec<EnrolledAgent>> {
        ensure!(valid_id(tenant), "invalid tenant identity");
        let client = self.checkout().await?;
        Ok(self.bounded(client.query("SELECT tenant_id,agent_id,created_at_unix,revoked_at_unix,credential_generation FROM managed_agent_enrollments WHERE tenant_id=$1 ORDER BY agent_id LIMIT 256", &[&tenant])).await?.into_iter().map(enrollment).collect())
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
        let result = self
            .deploy_managed_revision_tx(
                &tx,
                tenant,
                agent,
                revision,
                if rollback {
                    DeploymentMode::Rollback
                } else {
                    DeploymentMode::Activate
                },
                issuer,
            )
            .await?;
        self.bounded(tx.commit()).await?;
        Ok(result)
    }

    async fn deploy_managed_revision_tx(
        &self,
        tx: &Transaction<'_>,
        tenant: &str,
        agent: &str,
        revision: &str,
        mode: DeploymentMode,
        issuer: &ManagedIssuer,
    ) -> Result<ManagedDeployment> {
        let rollback = mode != DeploymentMode::Activate;
        self.lock_managed_agent(tx, tenant, agent).await?;
        let payload = self.bounded(tx.query_opt("SELECT policy_yaml,policy_sha256 FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3 AND approved_at_unix IS NOT NULL", &[&tenant,&agent,&revision])).await?.context("revision not approved or not found")?;
        let last = self.bounded(tx.query_opt("SELECT deployment_sequence,revision FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 ORDER BY deployment_sequence DESC LIMIT 1", &[&tenant,&agent])).await?;
        if mode == DeploymentMode::Rollback {
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
        deployment(row)
    }
    async fn assert_current_agent_credential(
        &self,
        tx: &Transaction<'_>,
        tenant: &str,
        agent: &str,
        bearer: &str,
    ) -> Result<()> {
        let token = bearer
            .strip_prefix("Bearer ")
            .context("invalid Agent authorization")?;
        let digest = credential_hash(token).context("invalid Agent credential")?;
        let authorized = self
            .bounded(tx.query_opt(
                "SELECT 1 FROM managed_agent_enrollments
             WHERE tenant_id=$1 AND agent_id=$2 AND token_hash=$3 AND revoked_at_unix IS NULL",
                &[&tenant, &agent, &digest],
            ))
            .await?;
        ensure!(authorized.is_some(), "Agent credential retired or revoked");
        Ok(())
    }

    pub(in crate::tenant_store) async fn deliver_authorized_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        bearer: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        self.deliver_managed_bundle_inner(tenant, agent, Some(bearer))
            .await
    }

    pub(in crate::tenant_store) async fn deliver_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        self.deliver_managed_bundle_inner(tenant, agent, None).await
    }
    async fn deliver_managed_bundle_inner(
        &self,
        tenant: &str,
        agent: &str,
        credential: Option<&str>,
    ) -> Result<Option<SignedManagedBundle>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        if let Some(bearer) = credential {
            self.assert_current_agent_credential(&tx, tenant, agent, bearer)
                .await?;
        }
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
    pub(in crate::tenant_store) async fn acknowledge_authorized_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        bearer: &str,
        report: &AppliedReport,
    ) -> Result<bool> {
        self.acknowledge_managed_bundle_inner(tenant, agent, Some(bearer), report)
            .await
    }
    pub(in crate::tenant_store) async fn acknowledge_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        report: &AppliedReport,
    ) -> Result<bool> {
        self.acknowledge_managed_bundle_inner(tenant, agent, None, report)
            .await
    }
    async fn acknowledge_managed_bundle_inner(
        &self,
        tenant: &str,
        agent: &str,
        credential: Option<&str>,
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
        if let Some(bearer) = credential {
            self.assert_current_agent_credential(&tx, tenant, agent, bearer)
                .await?;
        }
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
        drop(client);
        // Preserve accepted group gate progression after the exact authorized ACK,
        // outside the enrollment row lock and after returning the pool connection.
        let _ = self
            .check_and_advance_active_rollouts_for_agent(tenant, agent)
            .await;
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
        self.lock_managed_tenant(&tx, tenant).await?;
        let active = self.bounded(tx.query_opt(
            "SELECT 1 FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 AND phase IN ('pilot','standard','paused','rolling_back')",
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
        let mut connection = self.checkout().await?;
        let client = self.bounded(connection.transaction()).await?;
        self.lock_managed_tenant(&client, tenant).await?;
        self.ensure_group_tables(&*client).await?;
        let count = self.bounded(client.execute(
            "DELETE FROM managed_agent_group_members WHERE tenant_id=$1 AND group_id=$2 AND agent_id=$3",
            &[&tenant, &group_id, &agent_id],
        )).await?;
        self.bounded(client.commit()).await?;
        Ok(count > 0)
    }

    pub(in crate::tenant_store) async fn list_managed_group_members(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Vec<ManagedGroupMember>> {
        let client = self.checkout().await?;
        self.list_managed_group_members_query(&**client, tenant, group_id)
            .await
    }

    async fn list_managed_group_members_query<C: GenericClient + Sync>(
        &self,
        client: &C,
        tenant: &str,
        group_id: &str,
    ) -> Result<Vec<ManagedGroupMember>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");

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
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.bounded(tx.query_one(
            "SELECT id FROM tenants WHERE id=$1 AND active=TRUE FOR UPDATE",
            &[&tenant],
        ))
        .await?;

        let _started = self
            .start_managed_group_rollout_tx(&tx, tenant, group_id, revision, issuer)
            .await?;
        let result = self
            .get_managed_group_rollout_query(&*tx, tenant, group_id)
            .await?
            .context("rollout disappeared during transaction")?;
        self.bounded(tx.commit()).await?;
        Ok(result)
    }

    async fn start_managed_group_rollout_tx(
        &self,
        client: &Transaction<'_>,
        tenant: &str,
        group_id: &str,
        revision: &str,
        issuer: &ManagedIssuer,
    ) -> Result<ManagedGroupRollout> {
        let (_policy_yaml, policy_sha256, pilots, standards, prevs, initial_sequences) = {
            let rev_row = self.bounded(client.query_opt(
                "SELECT policy_yaml, policy_sha256 FROM managed_group_revisions WHERE tenant_id=$1 AND group_id=$2 AND revision=$3 AND approved_at_unix IS NOT NULL",
                &[&tenant, &group_id, &revision],
            )).await?;
            let rev_row = rev_row.context("group revision not approved or not found")?;
            let policy_yaml: String = rev_row.get(0);
            let policy_sha256: String = rev_row.get(1);

            if let Some(existing) = self
                .get_managed_group_rollout_query(client, tenant, group_id)
                .await?
            {
                if existing.revision == revision
                    && existing.policy_sha256 == policy_sha256
                    && existing.phase == RolloutPhase::Pilot
                {
                    let mut active_deployments = existing.active_deployments.clone();
                    let mut active_changed = false;
                    for pilot in &existing.pilot_agents {
                        if !active_deployments.contains_key(pilot) {
                            let init_seq =
                                existing.initial_sequences.get(pilot).copied().unwrap_or(0);
                            let existing_dep = self
                                .bounded(client.query_opt(
                                    "SELECT deployment_sequence, revision, policy_sha256, status
                                     FROM managed_agent_deployments
                                     WHERE tenant_id=$1 AND agent_id=$2
                                     ORDER BY deployment_sequence DESC LIMIT 1",
                                    &[&tenant, pilot],
                                ))
                                .await?;
                            let seq = if let Some(row) = existing_dep {
                                let d_seq: i64 = row.get(0);
                                let d_rev: String = row.get(1);
                                let d_sha: String = row.get(2);
                                let d_st: String = row.get(3);
                                let d_seq_u64 = d_seq as u64;
                                if d_seq_u64 > init_seq {
                                    if d_rev == revision
                                        && d_sha == policy_sha256
                                        && d_st != "rejected"
                                    {
                                        d_seq_u64
                                    } else if d_st == "rejected" {
                                        bail!(
                                            "conflict: candidate deployment sequence {} for pilot agent '{}' was rejected",
                                            d_seq_u64,
                                            pilot
                                        );
                                    } else {
                                        bail!(
                                            "conflict: pilot agent '{}' deployment was superseded by sequence {} (rev '{}')",
                                            pilot,
                                            d_seq_u64,
                                            d_rev
                                        );
                                    }
                                } else {
                                    let dep = self
                                        .deploy_managed_revision_tx(
                                            client,
                                            tenant,
                                            pilot,
                                            revision,
                                            DeploymentMode::Activate,
                                            issuer,
                                        )
                                        .await?;
                                    dep.deployment_sequence
                                }
                            } else {
                                let dep = self
                                    .deploy_managed_revision_tx(
                                        client,
                                        tenant,
                                        pilot,
                                        revision,
                                        DeploymentMode::Activate,
                                        issuer,
                                    )
                                    .await?;
                                dep.deployment_sequence
                            };
                            active_deployments.insert(pilot.clone(), seq);
                            active_changed = true;
                        }
                    }
                    if active_changed {
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts
                             SET active_deployments_json=$3, updated_at_unix=$4
                             WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                            &[
                                &tenant,
                                &group_id,
                                &serde_json::to_string(&active_deployments)?,
                                &now_unix(),
                                &existing.rollout_id,
                            ],
                        ))
                        .await?;
                    }
                    return Ok(ManagedGroupRollout {
                        active_deployments,
                        ..existing
                    });
                }
                if existing.revision == revision
                    && existing.issuer_key_id.as_deref() == Some(issuer.key_id())
                    && matches!(
                        existing.phase,
                        RolloutPhase::Standard | RolloutPhase::Completed
                    )
                {
                    return Ok(existing);
                }
            }
            let active = self.bounded(client.query_opt(
                "SELECT 1 FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 AND phase IN ('pilot','standard','paused','rolling_back')",
                &[&tenant, &group_id],
            )).await?;
            ensure!(
                active.is_none(),
                "active rollout already in progress for group '{}'",
                group_id
            );

            let members = self
                .list_managed_group_members_query(client, tenant, group_id)
                .await?;
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

            let mut all_new_members = std::collections::BTreeSet::new();
            for p in &pilots {
                all_new_members.insert(p.clone());
            }
            for s in &standards {
                all_new_members.insert(s.clone());
            }

            let active_rollouts = self
                .bounded(client.query(
                    "SELECT group_id, rollout_id, phase, pilot_agents_json, standard_agents_json
                 FROM managed_group_rollouts
                 WHERE tenant_id=$1 AND phase IN ('pilot','standard','paused','rolling_back')",
                    &[&tenant],
                ))
                .await?;

            for r in active_rollouts {
                let other_gid: String = r.get(0);
                let other_roid: String = r.get(1);
                let other_ph: String = r.get(2);
                let pilots_json: String = r.get(3);
                let stds_json: String = r.get(4);
                let other_pilots: Vec<String> =
                    serde_json::from_str(&pilots_json).unwrap_or_default();
                let other_stds: Vec<String> = serde_json::from_str(&stds_json).unwrap_or_default();
                for member in &all_new_members {
                    if other_pilots.contains(member) || other_stds.contains(member) {
                        bail!(
                            "agent '{}' is already enrolled in active rollout '{}' (group '{}', phase '{}')",
                            member, other_roid, other_gid, other_ph
                        );
                    }
                }
            }

            for member in &all_new_members {
                let unacked = self
                    .bounded(client.query_opt(
                        "SELECT deployment_sequence FROM managed_agent_deployments
                     WHERE tenant_id=$1 AND agent_id=$2 AND status IN ('issued','delivered')
                     AND deployment_sequence=(SELECT MAX(deployment_sequence) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2)
                     ORDER BY deployment_sequence DESC LIMIT 1",
                        &[&tenant, member],
                    ))
                    .await?;
                if let Some(r) = unacked {
                    let seq: i64 = r.get(0);
                    bail!(
                        "agent '{}' has unacknowledged deployment (sequence {}) and cannot join a new rollout",
                        member, seq
                    );
                }
            }

            let mut initial_sequences = std::collections::BTreeMap::new();
            for member in &all_new_members {
                let row = self.bounded(client.query_one("SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2", &[&tenant, member])).await?;
                initial_sequences.insert(member.clone(), u64::try_from(row.get::<_, i64>(0))?);
            }
            let mut prevs = std::collections::BTreeMap::new();
            for pilot in &pilots {
                let prev = self
                    .find_last_applied_revision_before_query(client, tenant, pilot, None)
                    .await?;
                prevs.insert(pilot.clone(), prev);
            }
            for std in &standards {
                let prev = self
                    .find_last_applied_revision_before_query(client, tenant, std, None)
                    .await?;
                prevs.insert(std.clone(), prev);
            }

            // Pre-flight check ALL pilots before ANY side effects or deployments:
            for pilot in pilots.iter().chain(standards.iter()) {
                self.lock_managed_agent(client, tenant, pilot).await?;
                let existing_meta = self
                    .bounded(client.query_opt(
                        "SELECT policy_sha256, approved_at_unix FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3",
                        &[&tenant, pilot, &revision],
                    ))
                    .await?;
                if let Some(r) = existing_meta {
                    let sha: String = r.get(0);
                    let approved_at: Option<i64> = r.get(1);
                    ensure!(
                        sha == policy_sha256,
                        "revision collision on pilot agent '{}': existing revision '{}' has different digest",
                        pilot, revision
                    );
                    ensure!(
                        approved_at.is_some(),
                        "revision '{}' for pilot agent '{}' is not approved",
                        revision,
                        pilot
                    );
                }
            }

            for pilot in &pilots {
                let existing_sha = self
                    .bounded(client.query_opt(
                        "SELECT policy_sha256 FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3",
                        &[&tenant, pilot, &revision],
                    ))
                    .await?;
                if existing_sha.is_none() {
                    self.bounded(client.execute(
                        "INSERT INTO managed_agent_revisions (tenant_id, agent_id, revision, policy_yaml, policy_sha256, approved_at_unix)
                         VALUES ($1,$2,$3,$4,$5,$6)",
                        &[&tenant, pilot, &revision, &policy_yaml, &policy_sha256, &now_unix()],
                    ))
                    .await?;
                }
            }
            (
                policy_yaml,
                policy_sha256,
                pilots,
                standards,
                prevs,
                initial_sequences,
            )
        };

        let rollout_id = format!("ro_{}", random_base64url(12));
        let now = now_unix();
        let phase = RolloutPhase::Pilot;

        self.bounded(client.execute(
            "INSERT INTO managed_group_rollouts
             (tenant_id, group_id, rollout_id, revision, policy_sha256, issuer_key_id, phase,
              pilot_agents_json, standard_agents_json, active_deployments_json, previous_revisions_json,
              failure_reason, created_at_unix, updated_at_unix, initial_sequences_json)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$12,$13)",
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
                &serde_json::to_string(&std::collections::BTreeMap::<String, u64>::new())?,
                &serde_json::to_string(&prevs)?,
                &now,
                &serde_json::to_string(&initial_sequences)?,
            ],
        )).await?;

        let mut active_deployments = std::collections::BTreeMap::new();
        for pilot in &pilots {
            let dep = self
                .deploy_managed_revision_tx(
                    client,
                    tenant,
                    pilot,
                    revision,
                    DeploymentMode::Activate,
                    issuer,
                )
                .await?;
            let seq = dep.deployment_sequence;
            active_deployments.insert(pilot.clone(), seq);
            self.bounded(client.execute(
                "UPDATE managed_group_rollouts
                 SET active_deployments_json=$3, updated_at_unix=$4
                 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                &[
                    &tenant,
                    &group_id,
                    &serde_json::to_string(&active_deployments)?,
                    &now_unix(),
                    &rollout_id,
                ],
            ))
            .await?;
        }

        Ok(ManagedGroupRollout {
            agents: Default::default(),
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
            initial_sequences,
            previous_revisions: prevs,
            failure_reason: None,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    async fn find_last_applied_revision_before_query<C: GenericClient + Sync>(
        &self,
        client: &C,
        tenant: &str,
        agent: &str,
        before_seq: Option<u64>,
    ) -> Result<Option<String>> {
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
        let mut client = self.checkout().await?;
        let tx = self
            .bounded(
                client
                    .build_transaction()
                    .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                    .read_only(true)
                    .start(),
            )
            .await?;
        let plan = self
            .get_managed_group_rollout_query(&*tx, tenant, group_id)
            .await?;
        self.bounded(tx.commit()).await?;
        Ok(plan)
    }

    async fn get_managed_group_rollout_query<C: GenericClient + Sync>(
        &self,
        client: &C,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ManagedGroupRollout>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");

        let row = self.bounded(client.query_opt(
            "SELECT rollout_id, revision, policy_sha256, issuer_key_id, phase,
                    pilot_agents_json, standard_agents_json, active_deployments_json,
                    previous_revisions_json, failure_reason, created_at_unix, updated_at_unix, initial_sequences_json
             FROM managed_group_rollouts WHERE tenant_id=$1 AND group_id=$2 ORDER BY plan_sequence DESC LIMIT 1",
            &[&tenant, &group_id],
        )).await?;
        let Some(r) = row else { return Ok(None) };
        let phase_str: String = r.get(4);
        let pilot_json: String = r.get(5);
        let standard_json: String = r.get(6);
        let active_json: String = r.get(7);
        let prev_json: String = r.get(8);
        let mut plan = ManagedGroupRollout {
            agents: Default::default(),
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
            initial_sequences: serde_json::from_str(&r.get::<_, String>(12))?,
            previous_revisions: serde_json::from_str(&prev_json)?,
            failure_reason: r.get(9),
            created_at_unix: r.get(10),
            updated_at_unix: r.get(11),
        };
        for agent in plan.pilot_agents.iter().chain(plan.standard_agents.iter()) {
            let expected_sequence = plan.active_deployments.get(agent).map(|s| *s as i64);
            let rows=self.bounded(client.query("SELECT tenant_id,agent_id,deployment_sequence,revision,policy_sha256,action,status,issued_at_unix,applied_at_unix FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND (deployment_sequence=$3 OR deployment_sequence=(SELECT MAX(deployment_sequence) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2)) ORDER BY deployment_sequence DESC", &[&tenant,agent,&expected_sequence])).await?;
            let deployments = rows
                .into_iter()
                .map(deployment)
                .collect::<Result<Vec<_>>>()?;
            let latest = deployments.first().cloned();
            let expected = deployments
                .into_iter()
                .find(|d| Some(d.deployment_sequence as i64) == expected_sequence);
            let row=self.bounded(client.query_one("SELECT NOT EXISTS(SELECT 1 FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at_unix IS NULL)", &[&tenant,agent])).await?;
            plan.agents.insert(
                agent.clone(),
                rollout_agent_status(&plan, agent, latest, expected, row.get(0)),
            );
        }
        Ok(Some(plan))
    }

    pub(in crate::tenant_store) async fn advance_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: Option<&ManagedIssuer>,
    ) -> Result<Option<ManagedGroupRollout>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.bounded(tx.query_one(
            "SELECT id FROM tenants WHERE id=$1 AND active=TRUE FOR UPDATE",
            &[&tenant],
        ))
        .await?;

        let result = self
            .advance_managed_group_rollout_tx(&tx, tenant, group_id, issuer)
            .await?;
        let result = if result.is_some() {
            self.get_managed_group_rollout_query(&*tx, tenant, group_id)
                .await?
        } else {
            None
        };
        self.bounded(tx.commit()).await?;
        Ok(result)
    }

    async fn advance_managed_group_rollout_tx(
        &self,
        client: &Transaction<'_>,
        tenant: &str,
        group_id: &str,
        issuer: Option<&ManagedIssuer>,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self
            .get_managed_group_rollout_query(client, tenant, group_id)
            .await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        if rollout.phase != RolloutPhase::Pilot
            && rollout.phase != RolloutPhase::Standard
            && rollout.phase != RolloutPhase::RollingBack
        {
            return Ok(Some(rollout));
        }

        let now = now_unix();

        if matches!(rollout.phase, RolloutPhase::Pilot | RolloutPhase::Standard)
            && rollout
                .pilot_agents
                .iter()
                .chain(rollout.standard_agents.iter())
                .any(|agent| !rollout.initial_sequences.contains_key(agent))
        {
            let reason = "legacy rollout has no frozen deployment inventory; progression refused; inspect and request rollback".to_string();
            self.bounded(client.execute("UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5", &[&tenant,&group_id,&reason,&now,&rollout.rollout_id])).await?;
            rollout.phase = RolloutPhase::Failed;
            rollout.failure_reason = Some(reason);
            rollout.updated_at_unix = now;
            return Ok(Some(rollout));
        }
        if matches!(rollout.phase, RolloutPhase::Pilot | RolloutPhase::Standard) {
            for (agent, seq) in &rollout.active_deployments {
                let row = self.bounded(client.query_one("SELECT EXISTS(SELECT 1 FROM managed_agent_deployments d JOIN managed_agent_enrollments e USING(tenant_id,agent_id) WHERE d.tenant_id=$1 AND d.agent_id=$2 AND d.deployment_sequence=$3 AND d.revision=$4 AND d.policy_sha256=$5 AND e.revoked_at_unix IS NULL AND d.deployment_sequence=(SELECT MAX(deployment_sequence) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2))", &[&tenant,agent,&(*seq as i64),&rollout.revision,&rollout.policy_sha256])).await?;
                if !row.get::<_, bool>(0) {
                    let reason = format!(
                        "conflict: rollout deployment {} for agent '{}' was superseded or revoked",
                        seq, agent
                    );
                    self.bounded(client.execute("UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5", &[&tenant,&group_id,&reason,&now,&rollout.rollout_id])).await?;
                    rollout.phase = RolloutPhase::Failed;
                    rollout.failure_reason = Some(reason);
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }
            }
        }

        match rollout.phase {
            RolloutPhase::Paused => Ok(Some(rollout)),
            RolloutPhase::RollingBack => {
                let mut all_applied = true;
                let mut conflict = None;
                for (agent, seq) in &rollout.active_deployments {
                    let s = *seq as i64;
                    let latest = self
                        .bounded(client.query_opt(
                            "SELECT deployment_sequence, revision, policy_sha256, status, issued_at_unix, applied_at_unix
                         FROM managed_agent_deployments
                         WHERE tenant_id=$1 AND agent_id=$2
                         ORDER BY deployment_sequence DESC LIMIT 1",
                            &[&tenant, agent],
                        ))
                        .await?;
                    match latest {
                        Some(r) => {
                            let latest_seq: i64 = r.get(0);
                            let latest_rev: String = r.get(1);
                            let status: String = r.get(3);
                            if latest_seq != s {
                                conflict = Some(format!(
                                    "conflict: rollback deployment {} for agent '{}' was superseded by sequence {}",
                                    seq, agent, latest_seq
                                ));
                                break;
                            }
                            let expected_baseline = rollout
                                .previous_revisions
                                .get(agent)
                                .and_then(|x| x.as_ref());
                            if let Some(exp) = expected_baseline {
                                if &latest_rev != exp {
                                    conflict = Some(format!(
                                        "conflict: rollback deployment {} for agent '{}' was issued for revision '{}', but expected baseline '{}'",
                                        seq, agent, latest_rev, exp
                                    ));
                                    break;
                                }
                            } else {
                                conflict = Some(format!(
                                    "cannot count candidate as confirmed rollback: agent '{}' has no baseline",
                                    agent
                                ));
                                break;
                            }
                            let issued_at: i64 = r.get(4);
                            let applied_at: Option<i64> = r.get(5);
                            if status == "rejected"
                                || acknowledgement_overdue(&status, issued_at, applied_at, now)
                            {
                                conflict = Some(format!("rollback unresolved: agent '{}' rejected or timed out awaiting baseline acknowledgement",agent));
                                break;
                            }
                            if status != "applied" {
                                all_applied = false;
                            }
                        }
                        None => {
                            all_applied = false;
                        }
                    }
                }

                let mut deployed_agents = Vec::new();
                for member in rollout
                    .pilot_agents
                    .iter()
                    .chain(rollout.standard_agents.iter())
                {
                    let has_dep = self
                        .bounded(client.query_opt(
                            "SELECT 1 FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3 AND policy_sha256=$4 AND deployment_sequence > $5 LIMIT 1",
                            &[&tenant, member, &rollout.revision, &rollout.policy_sha256, &(rollout.initial_sequences.get(member).copied().unwrap_or(u64::MAX) as i64)],
                        ))
                        .await?
                        .is_some();
                    if has_dep {
                        deployed_agents.push(member.clone());
                    }
                }

                let mut unresolved_agents = Vec::new();
                for agent in &deployed_agents {
                    if rollout
                        .previous_revisions
                        .get(agent)
                        .and_then(|x| x.as_ref())
                        .is_none()
                    {
                        unresolved_agents.push(agent.clone());
                    }
                }

                if let Some(reason) = conflict {
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                        &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::Failed;
                    rollout.failure_reason = Some(reason);
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }
                if all_applied && !rollout.active_deployments.is_empty() {
                    if !unresolved_agents.is_empty() {
                        let reason = format!(
                            "rollback unresolved: agent '{}' has no restorable baseline and remains on candidate revision '{}'",
                            unresolved_agents.join(", "),
                            rollout.revision
                        );
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                            &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
                        )).await?;
                        rollout.phase = RolloutPhase::Failed;
                        rollout.failure_reason = Some(reason);
                        rollout.updated_at_unix = now;
                        return Ok(Some(rollout));
                    } else {
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts SET phase='rolled_back', updated_at_unix=$3 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$4",
                            &[&tenant, &group_id, &now, &rollout.rollout_id],
                        )).await?;
                        rollout.phase = RolloutPhase::RolledBack;
                        rollout.updated_at_unix = now;
                        return Ok(Some(rollout));
                    }
                }
                Ok(Some(rollout))
            }
            RolloutPhase::Pilot => {
                for p in &rollout.pilot_agents {
                    if !rollout.active_deployments.contains_key(p) {
                        let init_seq = rollout.initial_sequences.get(p).copied().unwrap_or(0);
                        let existing_dep = self
                            .bounded(client.query_opt(
                                "SELECT deployment_sequence, revision, policy_sha256, status
                                  FROM managed_agent_deployments
                                  WHERE tenant_id=$1 AND agent_id=$2
                                  ORDER BY deployment_sequence DESC LIMIT 1",
                                &[&tenant, p],
                            ))
                            .await?;
                        if let Some(row) = existing_dep {
                            let d_seq: i64 = row.get(0);
                            let d_rev: String = row.get(1);
                            let d_sha: String = row.get(2);
                            let d_st: String = row.get(3);
                            let d_seq_u64 = d_seq as u64;
                            if d_seq_u64 > init_seq {
                                if d_rev != rollout.revision || d_sha != rollout.policy_sha256 {
                                    let reason = format!(
                                        "conflict: canary deployment for pilot agent '{}' was superseded by sequence {} (rev '{}')",
                                        p, d_seq_u64, d_rev
                                    );
                                    self.bounded(client.execute(
                                        "UPDATE managed_group_rollouts
                                         SET phase='failed', failure_reason=$3, updated_at_unix=$4
                                         WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                                        &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
                                    ))
                                    .await?;
                                    rollout.phase = RolloutPhase::Failed;
                                    rollout.failure_reason = Some(reason);
                                    rollout.updated_at_unix = now;
                                    return Ok(Some(rollout));
                                } else if d_st == "rejected" {
                                    let reason = format!(
                                        "conflict: candidate deployment sequence {} for pilot agent '{}' was rejected",
                                        d_seq_u64, p
                                    );
                                    self.bounded(client.execute(
                                        "UPDATE managed_group_rollouts
                                         SET phase='failed', failure_reason=$3, updated_at_unix=$4
                                         WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                                        &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
                                    ))
                                    .await?;
                                    rollout.phase = RolloutPhase::Failed;
                                    rollout.failure_reason = Some(reason);
                                    rollout.updated_at_unix = now;
                                    return Ok(Some(rollout));
                                }
                            }
                        }
                    }
                }

                let mut active_changed = false;
                for p in &rollout.pilot_agents {
                    if !rollout.active_deployments.contains_key(p) {
                        let init_seq = rollout.initial_sequences.get(p).copied().unwrap_or(0);
                        let existing_dep = self
                            .bounded(client.query_opt(
                                "SELECT deployment_sequence, revision, policy_sha256, status
                                  FROM managed_agent_deployments
                                  WHERE tenant_id=$1 AND agent_id=$2
                                  ORDER BY deployment_sequence DESC LIMIT 1",
                                &[&tenant, p],
                            ))
                            .await?;
                        let seq = if let Some(row) = existing_dep {
                            let d_seq: i64 = row.get(0);
                            let d_rev: String = row.get(1);
                            let d_sha: String = row.get(2);
                            let d_st: String = row.get(3);
                            let d_seq_u64 = d_seq as u64;
                            if d_seq_u64 > init_seq
                                && d_rev == rollout.revision
                                && d_sha == rollout.policy_sha256
                                && d_st != "rejected"
                            {
                                d_seq_u64
                            } else {
                                let default_issuer = ManagedIssuer::from_environment_for_key(
                                    rollout.issuer_key_id.as_deref(),
                                )
                                .ok();
                                let signing_issuer = default_issuer.as_ref().or(issuer);
                                let signing_issuer = signing_issuer.context(
                                    "signing issuer unavailable to issue missing pilot deployment",
                                )?;
                                let dep = self
                                    .deploy_managed_revision_tx(
                                        client,
                                        tenant,
                                        p,
                                        &rollout.revision,
                                        DeploymentMode::Activate,
                                        signing_issuer,
                                    )
                                    .await?;
                                dep.deployment_sequence
                            }
                        } else {
                            let default_issuer = ManagedIssuer::from_environment_for_key(
                                rollout.issuer_key_id.as_deref(),
                            )
                            .ok();
                            let signing_issuer = default_issuer.as_ref().or(issuer);
                            let signing_issuer = signing_issuer.context(
                                "signing issuer unavailable to issue missing pilot deployment",
                            )?;
                            let dep = self
                                .deploy_managed_revision_tx(
                                    client,
                                    tenant,
                                    p,
                                    &rollout.revision,
                                    DeploymentMode::Activate,
                                    signing_issuer,
                                )
                                .await?;
                            dep.deployment_sequence
                        };
                        rollout.active_deployments.insert(p.clone(), seq);
                        active_changed = true;
                    }
                }
                if active_changed {
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts
                         SET active_deployments_json=$3, updated_at_unix=$4
                         WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                        &[
                            &tenant,
                            &group_id,
                            &serde_json::to_string(&rollout.active_deployments)?,
                            &now,
                            &rollout.rollout_id,
                        ],
                    ))
                    .await?;
                }

                let mut any_rejected = None;
                let mut all_applied = true;
                let mut conflict = None;
                for p in &rollout.pilot_agents {
                    let seq = match rollout.active_deployments.get(p) {
                        Some(&s) => s as i64,
                        None => {
                            all_applied = false;
                            continue;
                        }
                    };
                    let latest = self.bounded(client.query_opt(
                        "SELECT deployment_sequence, revision, policy_sha256, status, issued_at_unix, applied_at_unix
                         FROM managed_agent_deployments
                         WHERE tenant_id=$1 AND agent_id=$2
                         ORDER BY deployment_sequence DESC LIMIT 1",
                        &[&tenant, p],
                    )).await?;

                    match latest {
                        Some(r) => {
                            let latest_seq: i64 = r.get(0);
                            let latest_rev: String = r.get(1);
                            let latest_sha: String = r.get(2);
                            let status: String = r.get(3);
                            let issued_at: i64 = r.get(4);
                            let applied_at: Option<i64> = r.get(5);

                            if latest_seq != seq
                                || latest_rev != rollout.revision
                                || latest_sha != rollout.policy_sha256
                            {
                                conflict = Some(format!(
                                    "conflict: canary deployment {} for agent '{}' was superseded by sequence {} (rev '{}')",
                                    seq, p, latest_seq, latest_rev
                                ));
                                break;
                            }
                            if acknowledgement_overdue(&status, issued_at, applied_at, now) {
                                any_rejected=Some((p.clone(),format!("pilot agent '{}' timed out awaiting policy acknowledgement (>300s)",p)));
                                break;
                            }
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
                                // Acknowledged matching candidate
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
                        }
                        None => {
                            all_applied = false;
                        }
                    }
                }

                if let Some(reason) = conflict {
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                        &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::Failed;
                    rollout.failure_reason = Some(reason);
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }

                if let Some((_rejected_agent, reason)) = any_rejected {
                    let mut to_rollback = Vec::new();
                    let mut unresolved = Vec::new();
                    for p in &rollout.pilot_agents {
                        let prev = rollout
                            .previous_revisions
                            .get(p)
                            .and_then(|x| x.as_ref())
                            .cloned();

                        if let Some(p_rev) = prev {
                            if !to_rollback.iter().any(|(a, _)| a == p) {
                                to_rollback.push((p.clone(), p_rev));
                            }
                        } else if !unresolved.contains(p) {
                            unresolved.push(p.clone());
                        }
                    }

                    if to_rollback.is_empty() && !unresolved.is_empty() {
                        let fail_reason = format!(
                            "{}; rollback unresolved: agents [{}] have no restorable applied baseline",
                            reason,
                            unresolved.join(", ")
                        );
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                            &[&tenant, &group_id, &fail_reason, &now, &rollout.rollout_id],
                        )).await?;
                        rollout.phase = RolloutPhase::Failed;
                        rollout.failure_reason = Some(fail_reason);
                        rollout.updated_at_unix = now;
                        return Ok(Some(rollout));
                    }

                    let default_issuer = ManagedIssuer::from_environment().ok();
                    let signing_issuer = default_issuer.as_ref().or(issuer);
                    let signing_issuer = match signing_issuer {
                        Some(iss) => iss,
                        None => {
                            bail!("configured signing issuer is unavailable for rollback deployment: {}", reason);
                        }
                    };
                    rollout.active_deployments.clear();
                    for (agent, prev) in to_rollback {
                        let dep = self
                            .deploy_managed_revision_tx(
                                client,
                                tenant,
                                &agent,
                                &prev,
                                DeploymentMode::RestoreBaseline,
                                signing_issuer,
                            )
                            .await?;
                        let seq = dep.deployment_sequence;
                        rollout.active_deployments.insert(agent, seq);
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

                    for agent in &rollout.standard_agents {
                        self.lock_managed_agent(client, tenant, agent).await?;
                        let row = self.bounded(client.query_one("SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2", &[&tenant, agent])).await?;
                        let latest = u64::try_from(row.get::<_, i64>(0))?;
                        let expected = rollout
                            .active_deployments
                            .get(agent)
                            .or_else(|| rollout.initial_sequences.get(agent));
                        if expected.copied() != Some(latest) {
                            let reason = format!("conflict: standard agent '{}' changed deployment after the plan was frozen", agent);
                            self.bounded(client.execute("UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5", &[&tenant, &group_id, &reason, &now, &rollout.rollout_id])).await?;
                            rollout.phase = RolloutPhase::Failed;
                            rollout.failure_reason = Some(reason);
                            rollout.updated_at_unix = now;
                            return Ok(Some(rollout));
                        }
                    }
                    // Pre-validate that all standard workers can be safely targeted:
                    // If revision already exists, it MUST match candidate sha256 and MUST be approved.
                    // If any standard agent fails pre-validation, abort promotion before side effects.
                    for w in &rollout.standard_agents {
                        let existing_meta = self.bounded(client.query_opt(
                            "SELECT policy_sha256, approved_at_unix FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3",
                            &[&tenant, w, &rollout.revision],
                        )).await?;
                        if let Some(r) = existing_meta {
                            let sha: String = r.get(0);
                            let approved_at: Option<i64> = r.get(1);
                            ensure!(
                                sha == rollout.policy_sha256,
                                "revision collision on standard agent '{}': existing revision '{}' has different digest",
                                w, rollout.revision
                            );
                            ensure!(
                                approved_at.is_some(),
                                "candidate revision '{}' on standard agent '{}' is not approved",
                                rollout.revision,
                                w
                            );
                        }
                    }

                    let default_issuer =
                        ManagedIssuer::from_environment_for_key(rollout.issuer_key_id.as_deref())
                            .ok();
                    let signing_issuer = default_issuer.as_ref().or(issuer);
                    let signing_issuer = match signing_issuer {
                        Some(iss) => iss,
                        None => {
                            bail!("configured signing issuer is unavailable for standard wave deployment");
                        }
                    };

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
                        if existing_sha.is_none() {
                            self.bounded(client.execute(
                                "INSERT INTO managed_agent_revisions (tenant_id, agent_id, revision, policy_yaml, policy_sha256, approved_at_unix)
                                 VALUES ($1,$2,$3,$4,$5,$6)",
                                &[&tenant, w, &rollout.revision, &yaml, &rollout.policy_sha256, &now],
                            )).await?;
                        }
                    }

                    for w in &rollout.standard_agents {
                        if rollout.active_deployments.contains_key(w) {
                            continue;
                        }
                        let dep = self
                            .deploy_managed_revision_tx(
                                client,
                                tenant,
                                w,
                                &rollout.revision,
                                DeploymentMode::Activate,
                                signing_issuer,
                            )
                            .await?;
                        let seq = dep.deployment_sequence;
                        rollout.active_deployments.insert(w.clone(), seq);
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts
                             SET active_deployments_json=$3, updated_at_unix=$4
                             WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                            &[
                                &tenant,
                                &group_id,
                                &serde_json::to_string(&rollout.active_deployments)?,
                                &now,
                                &rollout.rollout_id,
                            ],
                        ))
                        .await?;
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
                let mut conflict = None;
                for w in &rollout.standard_agents {
                    let seq = match rollout.active_deployments.get(w) {
                        Some(&s) => s as i64,
                        None => {
                            all_applied = false;
                            continue;
                        }
                    };
                    let latest = self.bounded(client.query_opt(
                        "SELECT deployment_sequence, revision, policy_sha256, status, issued_at_unix, applied_at_unix
                         FROM managed_agent_deployments
                         WHERE tenant_id=$1 AND agent_id=$2
                         ORDER BY deployment_sequence DESC LIMIT 1",
                        &[&tenant, w],
                    )).await?;

                    match latest {
                        Some(r) => {
                            let latest_seq: i64 = r.get(0);
                            let latest_rev: String = r.get(1);
                            let latest_sha: String = r.get(2);
                            let status: String = r.get(3);
                            let issued_at: i64 = r.get(4);
                            let applied_at: Option<i64> = r.get(5);

                            if latest_seq != seq
                                || latest_rev != rollout.revision
                                || latest_sha != rollout.policy_sha256
                            {
                                conflict = Some(format!(
                                    "conflict: standard deployment {} for agent '{}' was superseded by sequence {} (rev '{}')",
                                    seq, w, latest_seq, latest_rev
                                ));
                                break;
                            }
                            if acknowledgement_overdue(&status, issued_at, applied_at, now) {
                                any_rejected=Some((w.clone(),format!("standard agent '{}' timed out awaiting policy acknowledgement (>300s)",w)));
                                break;
                            }
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
                                // Acknowledged matching candidate
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
                        }
                        None => {
                            all_applied = false;
                        }
                    }
                }

                if let Some(reason) = conflict {
                    self.bounded(client.execute(
                        "UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                        &[&tenant, &group_id, &reason, &now, &rollout.rollout_id],
                    )).await?;
                    rollout.phase = RolloutPhase::Failed;
                    rollout.failure_reason = Some(reason);
                    rollout.updated_at_unix = now;
                    return Ok(Some(rollout));
                }

                if let Some((_rejected_agent, reason)) = any_rejected {
                    let mut to_rollback = Vec::new();
                    let mut unresolved = Vec::new();
                    let mut deployed_agents = Vec::new();
                    for member in rollout
                        .pilot_agents
                        .iter()
                        .chain(rollout.standard_agents.iter())
                    {
                        let has_dep = self
                            .bounded(client.query_opt(
                                "SELECT 1 FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3 AND policy_sha256=$4 AND deployment_sequence > $5 LIMIT 1",
                                &[&tenant, member, &rollout.revision, &rollout.policy_sha256, &(rollout.initial_sequences.get(member).copied().unwrap_or(u64::MAX) as i64)],
                            ))
                            .await?
                            .is_some();
                        if has_dep {
                            deployed_agents.push(member.clone());
                        }
                    }
                    for agent in &deployed_agents {
                        let prev = rollout
                            .previous_revisions
                            .get(agent)
                            .and_then(|p| p.as_ref())
                            .cloned();

                        if let Some(p) = prev {
                            if !to_rollback.iter().any(|(a, _)| a == agent) {
                                to_rollback.push((agent.clone(), p));
                            }
                        } else if !unresolved.contains(agent) {
                            unresolved.push(agent.clone());
                        }
                    }

                    if to_rollback.is_empty() && !unresolved.is_empty() {
                        let fail_reason = format!(
                            "{}; rollback unresolved: agents [{}] have no restorable applied baseline",
                            reason,
                            unresolved.join(", ")
                        );
                        self.bounded(client.execute(
                            "UPDATE managed_group_rollouts SET phase='failed', failure_reason=$3, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
                            &[&tenant, &group_id, &fail_reason, &now, &rollout.rollout_id],
                        )).await?;
                        rollout.phase = RolloutPhase::Failed;
                        rollout.failure_reason = Some(fail_reason);
                        rollout.updated_at_unix = now;
                        return Ok(Some(rollout));
                    }

                    let default_issuer = ManagedIssuer::from_environment().ok();
                    let signing_issuer = default_issuer.as_ref().or(issuer);
                    let signing_issuer = match signing_issuer {
                        Some(iss) => iss,
                        None => {
                            bail!("configured signing issuer is unavailable for rollback deployment: {}", reason);
                        }
                    };
                    rollout.active_deployments.clear();
                    for (agent, prev) in to_rollback {
                        let dep = self
                            .deploy_managed_revision_tx(
                                client,
                                tenant,
                                &agent,
                                &prev,
                                DeploymentMode::RestoreBaseline,
                                signing_issuer,
                            )
                            .await?;
                        let seq = dep.deployment_sequence;
                        rollout.active_deployments.insert(agent, seq);
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
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.bounded(tx.query_one(
            "SELECT id FROM tenants WHERE id=$1 AND active=TRUE FOR UPDATE",
            &[&tenant],
        ))
        .await?;

        let result = self
            .rollback_managed_group_rollout_tx(&tx, tenant, group_id, issuer)
            .await?;
        let result = if result.is_some() {
            self.get_managed_group_rollout_query(&*tx, tenant, group_id)
                .await?
        } else {
            None
        };
        self.bounded(tx.commit()).await?;
        Ok(result)
    }

    async fn rollback_managed_group_rollout_tx(
        &self,
        client: &Transaction<'_>,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self
            .get_managed_group_rollout_query(client, tenant, group_id)
            .await?;
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
        let signing_issuer = default_issuer.as_ref().or(Some(issuer));
        let signing_issuer = match signing_issuer {
            Some(iss) => iss,
            None => {
                bail!("configured signing issuer is unavailable for rollback");
            }
        };

        let mut deployed_agents = Vec::new();
        for member in rollout
            .pilot_agents
            .iter()
            .chain(rollout.standard_agents.iter())
        {
            let has_dep = self
                .bounded(client.query_opt(
                    "SELECT 1 FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND revision=$3 AND policy_sha256=$4 AND deployment_sequence > $5 LIMIT 1",
                    &[&tenant, member, &rollout.revision, &rollout.policy_sha256, &(rollout.initial_sequences.get(member).copied().unwrap_or(u64::MAX) as i64)],
                ))
                .await?
                .is_some();
            if has_dep {
                deployed_agents.push(member.clone());
            }
        }
        if deployed_agents.is_empty() {
            for p in &rollout.pilot_agents {
                deployed_agents.push(p.clone());
            }
        }

        // The tenant lease makes this ownership check and all issuance atomic.
        let other_plans = self.bounded(client.query(
            "SELECT pilot_agents_json, standard_agents_json FROM managed_group_rollouts
             WHERE tenant_id=$1 AND rollout_id<>$2 AND phase IN ('pilot','standard','paused','rolling_back')",
            &[&tenant, &rollout.rollout_id],
        )).await?;
        for plan in other_plans {
            let pilots: Vec<String> = serde_json::from_str(plan.get::<_, &str>(0))?;
            let workers: Vec<String> = serde_json::from_str(plan.get::<_, &str>(1))?;
            for agent in &deployed_agents {
                ensure!(
                    !pilots.contains(agent) && !workers.contains(agent),
                    "conflict: agent '{}' is owned by another active rollout",
                    agent
                );
            }
        }
        for agent in &deployed_agents {
            let latest: i64 = self.bounded(client.query_one(
                "SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2",
                &[&tenant, agent],
            )).await?.get(0);
            ensure!(
                rollout.active_deployments.get(agent).copied() == Some(u64::try_from(latest)?),
                "conflict: agent '{}' deployment was superseded before rollback",
                agent
            );
        }

        let mut to_rollback = Vec::new();
        let mut unresolved = Vec::new();
        for agent in &deployed_agents {
            let prev = rollout
                .previous_revisions
                .get(agent)
                .and_then(|p| p.as_ref())
                .cloned();

            if let Some(p) = prev {
                if !to_rollback.iter().any(|(a, _)| a == agent) {
                    to_rollback.push((agent.clone(), p));
                }
            } else if !unresolved.contains(agent) {
                unresolved.push(agent.clone());
            }
        }

        if to_rollback.is_empty() && !unresolved.is_empty() {
            bail!("cannot rollback group rollout: no enrolled agents have a prior restorable applied baseline");
        }

        rollout.active_deployments.clear();
        for (agent, prev) in to_rollback {
            let dep = self
                .deploy_managed_revision_tx(
                    client,
                    tenant,
                    &agent,
                    &prev,
                    DeploymentMode::RestoreBaseline,
                    signing_issuer,
                )
                .await?;
            let seq = dep.deployment_sequence;
            rollout.active_deployments.insert(agent, seq);
        }

        let now = now_unix();
        let reason = "operator requested rollback".to_string();
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
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.bounded(tx.query_one(
            "SELECT id FROM tenants WHERE id=$1 AND active=TRUE FOR UPDATE",
            &[&tenant],
        ))
        .await?;

        let result = self
            .pause_managed_group_rollout_tx(&tx, tenant, group_id)
            .await?;
        let result = if result.is_some() {
            self.get_managed_group_rollout_query(&*tx, tenant, group_id)
                .await?
        } else {
            None
        };
        self.bounded(tx.commit()).await?;
        Ok(result)
    }

    async fn pause_managed_group_rollout_tx(
        &self,
        client: &Transaction<'_>,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self
            .get_managed_group_rollout_query(client, tenant, group_id)
            .await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        if rollout.phase == RolloutPhase::Paused {
            return Ok(Some(rollout));
        }
        ensure!(
            rollout.phase == RolloutPhase::Pilot || rollout.phase == RolloutPhase::Standard,
            "cannot pause rollout in phase '{}'",
            rollout.phase.as_str()
        );
        let orig_phase = rollout.phase;
        let reason = format!("paused:{}", orig_phase.as_str());
        let now = now_unix();
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
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.bounded(tx.query_one(
            "SELECT id FROM tenants WHERE id=$1 AND active=TRUE FOR UPDATE",
            &[&tenant],
        ))
        .await?;

        let result = self
            .resume_managed_group_rollout_tx(&tx, tenant, group_id, issuer)
            .await?;
        let result = if result.is_some() {
            self.get_managed_group_rollout_query(&*tx, tenant, group_id)
                .await?
        } else {
            None
        };
        self.bounded(tx.commit()).await?;
        Ok(result)
    }

    async fn resume_managed_group_rollout_tx(
        &self,
        client: &Transaction<'_>,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        let current = self
            .get_managed_group_rollout_query(client, tenant, group_id)
            .await?;
        let Some(mut rollout) = current else {
            return Ok(None);
        };
        if matches!(
            rollout.phase,
            RolloutPhase::Pilot | RolloutPhase::Standard | RolloutPhase::Completed
        ) {
            return Ok(Some(rollout));
        }
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
        self.bounded(client.execute(
            "UPDATE managed_group_rollouts SET phase=$3, failure_reason=NULL, updated_at_unix=$4 WHERE tenant_id=$1 AND group_id=$2 AND rollout_id=$5",
            &[&tenant, &group_id, &restored_phase.as_str(), &now, &rollout.rollout_id],
        )).await?;
        rollout.phase = restored_phase;
        rollout.failure_reason = None;
        rollout.updated_at_unix = now;

        self.advance_managed_group_rollout_tx(client, tenant, group_id, Some(issuer))
            .await
    }

    pub(in crate::tenant_store) async fn check_and_advance_active_rollouts_for_agent(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<()> {
        let client = self.checkout().await?;
        let has_groups = self
            .bounded(client.query_opt(
                "SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='managed_agent_groups'",
                &[],
            ))
            .await?
            .is_some();
        if !has_groups {
            return Ok(());
        }
        let rows = self
            .bounded(client.query(
                "SELECT group_id, issuer_key_id, active_deployments_json
             FROM managed_group_rollouts
             WHERE tenant_id=$1 AND phase IN ('pilot','standard','rolling_back')",
                &[&tenant],
            ))
            .await?;

        drop(client);
        // ACKs belong to the persisted deployment inventory, even if live membership changes.
        for r in rows {
            let gid: String = r.get(0);
            let active_json: String = r.get(2);
            let active_deps: std::collections::BTreeMap<String, u64> =
                serde_json::from_str(&active_json)?;
            if !active_deps.contains_key(agent) {
                continue;
            }
            let issuer_key_id: Option<String> = r.get(1);
            let issuer = ManagedIssuer::from_environment_for_key(issuer_key_id.as_deref()).ok();
            let _ = self
                .advance_managed_group_rollout(tenant, &gid, issuer.as_ref())
                .await;
        }
        Ok(())
    }
}
