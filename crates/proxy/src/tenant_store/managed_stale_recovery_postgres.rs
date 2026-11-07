// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL facts and fence writes for SOU-242 stale-restore recovery. The
//! confirmation takes the same tenant and Agent row locks as issuance, so a
//! deployment cannot interleave with the re-derived state it binds.
use super::PostgresTenantStore;
use crate::tenant_store::{
    managed_policy::{ManagedIssuer, SignedManagedBundle},
    managed_stale_recovery::{
        check_confirmation, credential_digest, evaluate, fence_from_parts, revisions_digest,
        status, Completion, ConfirmRequest, Confirmed, Decision, Facts, Fence, LatestDeployment,
        Preview, Status, CONTRACT, FENCE_COLUMNS, POSTGRES_FENCE_HIGH, POSTGRES_RESTORED_FLOOR,
    },
    now_unix,
};
use anyhow::Result;
use deadpool_postgres::GenericClient;
use sha2::{Digest, Sha256};
use tokio_postgres::IsolationLevel;

const COMPLETION_SQL_PG: &str = "SELECT deployment_sequence,revision,policy_sha256,applied_at_unix FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND deployment_sequence>$3 AND issued_at_unix>=$4 AND status='applied' ORDER BY deployment_sequence LIMIT 1";

impl PostgresTenantStore {
    async fn stale_recovery_facts<C: GenericClient + Sync>(
        &self,
        c: &C,
        tenant: &str,
        agent: &str,
    ) -> Result<Facts> {
        let enrollment = self
            .bounded(c.query_opt(
                "SELECT revoked_at_unix,credential_generation,token_hash FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2",
                &[&tenant, &agent],
            ))
            .await?;
        let latest = self
            .bounded(c.query_opt(
                "SELECT deployment_sequence,revision,policy_sha256,status,bundle_json FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 ORDER BY deployment_sequence DESC LIMIT 1",
                &[&tenant, &agent],
            ))
            .await?
            .map(|r| LatestDeployment {
                sequence: r.get(0),
                revision: r.get(1),
                policy_sha256: r.get(2),
                status: r.get(3),
                bundle_json: r.get(4),
            });
        let fence_high: i64 = self
            .bounded(c.query_one(POSTGRES_FENCE_HIGH, &[&tenant, &agent]))
            .await?
            .get(0);
        let restored_floor: i64 = self
            .bounded(c.query_one(POSTGRES_RESTORED_FLOOR, &[&tenant, &agent]))
            .await?
            .get(0);
        let revisions: Vec<(String, String, Option<i64>)> = self
            .bounded(c.query(
                "SELECT revision,policy_sha256,approved_at_unix FROM managed_agent_revisions WHERE tenant_id=$1 AND agent_id=$2 ORDER BY revision COLLATE \"C\"",
                &[&tenant, &agent],
            ))
            .await?
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        let available: bool = self
            .bounded(c.query_one(super::agent_heartbeat::AVAILABLE, &[]))
            .await?
            .get(0);
        let heartbeat = if available {
            self.bounded(c.query_opt(
                &format!(
                    "SELECT {} FROM agent_observations.heartbeats WHERE tenant_id=$1 AND agent_id=$2",
                    crate::tenant_store::agent_heartbeat::POSTGRES_ROW_COLUMNS
                ),
                &[&tenant, &agent],
            ))
            .await?
            .map(|r| super::agent_heartbeat::row(&r))
        } else {
            None
        };
        let (enrolled, revoked, generation, credential) = match enrollment {
            Some(r) => (
                true,
                r.get::<_, Option<i64>>(0).is_some(),
                r.get::<_, i64>(1),
                credential_digest(&r.get::<_, Vec<u8>>(2)),
            ),
            None => (false, false, 0, String::new()),
        };
        Ok(Facts {
            enrolled,
            revoked,
            generation,
            credential_digest: credential,
            latest,
            restored_floor,
            fence_high,
            revisions_digest: revisions_digest(&revisions),
            heartbeat_available: available,
            heartbeat,
            now: now_unix(),
        })
    }

    async fn stale_recovery_fences<C: GenericClient + Sync>(
        &self,
        c: &C,
        tenant: &str,
        agent: &str,
    ) -> Result<Vec<Fence>> {
        let rows = self
            .bounded(c.query(
                &format!("SELECT {FENCE_COLUMNS} FROM managed_agent_recovery_fences WHERE tenant_id=$1 AND agent_id=$2 ORDER BY fence_sequence DESC LIMIT 20"),
                &[&tenant, &agent],
            ))
            .await?;
        let mut out = Vec::new();
        for r in rows {
            let (seq, at): (i64, i64) = (r.get(0), r.get(11));
            let completion = self
                .bounded(c.query_opt(COMPLETION_SQL_PG, &[&tenant, &agent, &seq, &at]))
                .await?
                .map(|d| Completion {
                    deployment_sequence: d.get(0),
                    revision: d.get(1),
                    policy_sha256: d.get(2),
                    applied_at_unix: d.get(3),
                });
            out.push(fence_from_parts(
                seq,
                r.get(1),
                r.get(2),
                r.get(3),
                r.get(4),
                r.get(5),
                r.get(6),
                (r.get(7), r.get(8)),
                r.get(9),
                r.get(10),
                at,
                completion,
            ));
        }
        Ok(out)
    }

    pub(in crate::tenant_store) async fn stale_recovery_preview(
        &self,
        tenant: &str,
        agent: &str,
        evidence: &SignedManagedBundle,
        issuer: &ManagedIssuer,
    ) -> Result<Decision<Preview>> {
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
        let facts = self.stale_recovery_facts(&tx, tenant, agent).await?;
        self.bounded(tx.commit()).await?;
        Ok(evaluate(tenant, agent, &facts, evidence, issuer).map(|v| v.preview))
    }

    pub(in crate::tenant_store) async fn stale_recovery_confirm(
        &self,
        tenant: &str,
        agent: &str,
        request: &ConfirmRequest,
        issuer: &ManagedIssuer,
        admin_id: &str,
    ) -> Result<Decision<Confirmed>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        // Same locks as issuance: tenant lease, then the live enrollment row.
        self.lock_managed_tenant(&tx, tenant).await?;
        self.bounded(tx.query_opt(
            "SELECT agent_id FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE",
            &[&tenant, &agent],
        ))
        .await?;
        let digest = serde_json::to_vec(&request.evidence)
            .map(|b| crate::tenant_store::managed_policy::hex(&Sha256::digest(&b)))?;
        if let Some(row) = self
            .bounded(tx.query_opt(
                "SELECT fence_sequence,state_binding FROM managed_agent_recovery_fences WHERE tenant_id=$1 AND agent_id=$2 AND evidence_bundle_sha256=$3",
                &[&tenant, &agent, &digest],
            ))
            .await?
        {
            let (seq, binding): (i64, String) = (row.get(0), row.get(1));
            if binding == request.state_binding {
                let fence = self
                    .stale_recovery_fences(&tx, tenant, agent)
                    .await?
                    .into_iter()
                    .find(|f| f.fence_sequence == seq);
                self.bounded(tx.commit()).await?;
                if let Some(fence) = fence {
                    return Ok(Ok(Confirmed {
                        contract_version: CONTRACT.into(),
                        replayed: true,
                        fence,
                    }));
                }
                anyhow::bail!("fence disappeared");
            }
        }
        let facts = self.stale_recovery_facts(&tx, tenant, agent).await?;
        let verified = match evaluate(tenant, agent, &facts, &request.evidence, issuer) {
            Ok(v) => v,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) =
            check_confirmation(&verified, &request.state_binding, &request.confirmation)
        {
            return Ok(Err(refusal));
        }
        let p = &verified.preview;
        let interval = p.unrecoverable_interval.as_ref();
        let (from, to) = (
            interval.map(|i| i.from_sequence),
            interval.map(|i| i.to_sequence),
        );
        self.bounded(tx.execute(
            "INSERT INTO managed_agent_recovery_fences (tenant_id,agent_id,fence_sequence,restored_sequence,evidence_revision,evidence_policy_sha256,evidence_bundle_sha256,issuer_key_id,issuer_public_key_sha256,credential_generation,state_binding,unrecoverable_from,unrecoverable_to,observed_at_unix,confirmed_by,confirmed_at_unix) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[
                &tenant,
                &agent,
                &p.evidence.deployment_sequence,
                &verified.restored_high,
                &p.evidence.revision,
                &p.evidence.policy_sha256,
                &p.evidence.bundle_sha256,
                &p.evidence.issuer_key_id,
                &p.issuer_public_key_sha256,
                &p.credential_generation,
                &p.state_binding,
                &from,
                &to,
                &p.observed_at_unix,
                &admin_id,
                &now_unix(),
            ],
        ))
        .await?;
        let fence = self
            .stale_recovery_fences(&tx, tenant, agent)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("fence not persisted"))?;
        self.bounded(tx.commit()).await?;
        Ok(Ok(Confirmed {
            contract_version: CONTRACT.into(),
            replayed: false,
            fence,
        }))
    }

    pub(in crate::tenant_store) async fn stale_recovery_status(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<Status>> {
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
            .bounded(tx.query_opt(
                "SELECT 1 FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2",
                &[&tenant, &agent],
            ))
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let restored: i64 = self
            .bounded(tx.query_one(
                "SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2",
                &[&tenant, &agent],
            ))
            .await?
            .get(0);
        let fences = self.stale_recovery_fences(&tx, tenant, agent).await?;
        self.bounded(tx.commit()).await?;
        Ok(Some(status(tenant, agent, restored, fences)))
    }
}
