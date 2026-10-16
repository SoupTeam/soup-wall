// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL managed Agent storage. The enrollment row serializes deployment,
//! delivery, acknowledgement and revocation for one tenant/Agent audience.
use super::PostgresTenantStore;
use crate::tenant_store::{
    agent_enrollment::{credential_hash, valid_id, validated_rotation},
    managed_policy::{exact_id, hex, MAX_YAML},
    now_unix, random_base64url, AppliedReport, EnrolledAgent, IssuedAgentCredential,
    RotationOutcome, RotationRequest,
    ManagedDeployment, ManagedIssuer, ManagedRevision, SignedManagedBundle,
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
        // Additive, idempotent upgrade for old version-26 enrollment tables.
        // Held under the existing advisory migration lock.
        self.bounded(tx.batch_execute(
            "ALTER TABLE managed_agent_enrollments
                ADD COLUMN IF NOT EXISTS credential_generation BIGINT NOT NULL DEFAULT 1 CHECK(credential_generation > 0);
             ALTER TABLE managed_agent_enrollments ADD COLUMN IF NOT EXISTS last_rotation_id TEXT;
             ALTER TABLE managed_agent_enrollments ADD COLUMN IF NOT EXISTS last_rotation_expected_generation BIGINT;
             ALTER TABLE managed_agent_enrollments ADD COLUMN IF NOT EXISTS last_rotation_digest BYTEA;"
        )).await?;
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
    pub(in crate::tenant_store) async fn rotate_managed_agent(
        &self, tenant: &str, agent: &str, input: &RotationRequest
    ) -> Result<RotationOutcome> {
        let new_hash = validated_rotation(input)?;
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        let row = self.bounded(tx.query_one(
            "SELECT token_hash,credential_generation,last_rotation_id,
                    last_rotation_expected_generation,last_rotation_digest
             FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE",
            &[&tenant,&agent]
        )).await?;
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
                tenant_id: tenant.into(), agent_id: agent.into(), generation,
                operation_id: input.operation_id.clone(), already_applied: true,
            });
        }
        ensure!(last_id.as_deref() != Some(&input.operation_id),
            "operation identifier reused with different parameters");
        ensure!(generation == input.expected_generation, "stale credential generation");
        ensure!(old_hash != new_hash, "replacement must differ from current credential");
        let next = generation.checked_add(1).context("credential generation exhausted")?;
        self.bounded(tx.execute(
            "UPDATE managed_agent_enrollments
             SET token_hash=$3,credential_generation=$4,last_rotation_id=$5,
                 last_rotation_expected_generation=$6,last_rotation_digest=$7
             WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at_unix IS NULL",
            &[&tenant,&agent,&new_hash,&next,&input.operation_id,&input.expected_generation,&new_hash]
        )).await?;
        self.bounded(tx.commit()).await?;
        Ok(RotationOutcome {
            tenant_id: tenant.into(), agent_id: agent.into(), generation: next,
            operation_id: input.operation_id.clone(), already_applied: false,
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
    async fn assert_current_agent_credential(
        &self, tx: &Transaction<'_>, tenant: &str, agent: &str, bearer: &str,
    ) -> Result<()> {
        let token = bearer.strip_prefix("Bearer ").context("invalid Agent authorization")?;
        let digest = credential_hash(token).context("invalid Agent credential")?;
        let authorized = self.bounded(tx.query_opt(
            "SELECT 1 FROM managed_agent_enrollments
             WHERE tenant_id=$1 AND agent_id=$2 AND token_hash=$3 AND revoked_at_unix IS NULL",
            &[&tenant,&agent,&digest],
        )).await?;
        ensure!(authorized.is_some(), "Agent credential retired or revoked");
        Ok(())
    }

    pub(in crate::tenant_store) async fn deliver_authorized_managed_bundle(
        &self, tenant: &str, agent: &str, bearer: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        self.deliver_managed_bundle_inner(tenant,agent,Some(bearer)).await
    }

    pub(in crate::tenant_store) async fn deliver_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        self.deliver_managed_bundle_inner(tenant,agent,None).await
    }
    async fn deliver_managed_bundle_inner(
        &self, tenant: &str, agent: &str, credential: Option<&str>
    ) -> Result<Option<SignedManagedBundle>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        self.lock_managed_agent(&tx, tenant, agent).await?;
        if let Some(bearer) = credential {
            self.assert_current_agent_credential(&tx,tenant,agent,bearer).await?;
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
        &self, tenant: &str, agent: &str, bearer: &str, report: &AppliedReport
    ) -> Result<bool> {
        self.acknowledge_managed_bundle_inner(tenant,agent,Some(bearer),report).await
    }
    pub(in crate::tenant_store) async fn acknowledge_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        report: &AppliedReport,
    ) -> Result<bool> {
        self.acknowledge_managed_bundle_inner(tenant,agent,None,report).await
    }
    async fn acknowledge_managed_bundle_inner(
        &self, tenant: &str, agent: &str, credential: Option<&str>, report: &AppliedReport
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
            self.assert_current_agent_credential(&tx,tenant,agent,bearer).await?;
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
}
