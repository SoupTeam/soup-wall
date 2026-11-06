// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL heartbeat store in the separate `agent_observations` schema.
//! The enrollment row is locked FOR SHARE in the same transaction, so a
//! concurrent rotation or revocation cannot interleave with a write.
use super::PostgresTenantStore;
use crate::tenant_store::{
    agent_enrollment::credential_hash,
    agent_heartbeat::{
        self, check_heartbeat, check_registration, registered, Heartbeat, HeartbeatStatus,
        ObservedPolicy, Outcome, Registered, Registration, Row, POSTGRES_ROW_COLUMNS,
    },
    now_unix, EnrolledAgent,
};
use anyhow::Result;
use tokio_postgres::Row as PgRow;

fn row(r: &PgRow) -> Row {
    let seq: Option<i64> = r.get(6);
    Row {
        generation: r.get(0),
        instance_id: r.get(1),
        registration_id: r.get(2),
        last_sequence: r.get(3),
        registered_at: r.get(4),
        received_at: r.get(5),
        policy: seq.map(|deployment_sequence| ObservedPolicy {
            deployment_sequence,
            revision: r.get(7),
            policy_sha256: r.get(8),
        }),
    }
}
const IDENTITY: &str =
    "SELECT a.tenant_id,a.agent_id,a.created_at_unix,a.revoked_at_unix,a.credential_generation
    FROM managed_agent_enrollments a JOIN tenants t ON t.id=a.tenant_id
    WHERE a.token_hash=$1 AND a.revoked_at_unix IS NULL AND t.active=TRUE FOR SHARE OF a";
const AVAILABLE: &str = "SELECT to_regclass('agent_observations.heartbeats') IS NOT NULL";

impl PostgresTenantStore {
    async fn heartbeat_identity(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        authorization: Option<&str>,
    ) -> Result<Option<EnrolledAgent>> {
        let Some(hash) = authorization
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(credential_hash)
        else {
            return Ok(None);
        };
        Ok(self
            .bounded(tx.query_opt(IDENTITY, &[&hash]))
            .await?
            .map(|r| EnrolledAgent {
                tenant_id: r.get(0),
                agent_id: r.get(1),
                created_at_unix: r.get(2),
                revoked_at_unix: r.get(3),
                credential_generation: r.get(4),
            }))
    }

    pub(in crate::tenant_store) async fn register_agent_heartbeat(
        &self,
        authorization: Option<&str>,
        request: &Registration,
    ) -> Result<Outcome<Registered>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        if !self
            .bounded(tx.query_one(AVAILABLE, &[]))
            .await?
            .get::<_, bool>(0)
        {
            return Ok(Outcome::Unavailable);
        }
        let Some(identity) = self.heartbeat_identity(&tx, authorization).await? else {
            return Ok(Outcome::Unauthorized);
        };
        if let Err(refusal) = check_registration(&identity, request) {
            return Ok(Outcome::Refused(refusal));
        }
        let id = agent_heartbeat::new_registration_id();
        self.bounded(tx.execute(
            "INSERT INTO agent_observations.heartbeats(tenant_id,agent_id,credential_generation,instance_id,registration_id,last_sequence,registered_at_unix)
             VALUES($1,$2,$3,$4,$5,0,$6)
             ON CONFLICT(tenant_id,agent_id) DO UPDATE SET credential_generation=excluded.credential_generation,
               instance_id=excluded.instance_id,registration_id=excluded.registration_id,last_sequence=0,
               registered_at_unix=excluded.registered_at_unix,received_at_unix=NULL,policy_sequence=NULL,
               policy_revision=NULL,policy_sha256=NULL",
            &[&identity.tenant_id, &identity.agent_id, &identity.credential_generation, &request.instance_id, &id, &now_unix()],
        ))
        .await?;
        self.bounded(tx.commit()).await?;
        Ok(Outcome::Accepted(registered(
            id,
            identity.credential_generation,
        )))
    }

    pub(in crate::tenant_store) async fn record_agent_heartbeat(
        &self,
        authorization: Option<&str>,
        request: &Heartbeat,
    ) -> Result<Outcome<()>> {
        let mut client = self.checkout().await?;
        let tx = self.bounded(client.transaction()).await?;
        if !self
            .bounded(tx.query_one(AVAILABLE, &[]))
            .await?
            .get::<_, bool>(0)
        {
            return Ok(Outcome::Unavailable);
        }
        let Some(identity) = self.heartbeat_identity(&tx, authorization).await? else {
            return Ok(Outcome::Unauthorized);
        };
        let current = self
            .bounded(tx.query_opt(
                &format!("SELECT {POSTGRES_ROW_COLUMNS} FROM agent_observations.heartbeats WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE"),
                &[&identity.tenant_id, &identity.agent_id],
            ))
            .await?
            .map(|r| row(&r));
        let now = now_unix();
        if let Err(refusal) = check_heartbeat(&identity, current.as_ref(), request, now) {
            return Ok(Outcome::Refused(refusal));
        }
        let p = request.observed_policy.as_ref();
        self.bounded(tx.execute(
            "UPDATE agent_observations.heartbeats SET last_sequence=$3,received_at_unix=$4,policy_sequence=$5,policy_revision=$6,policy_sha256=$7
             WHERE tenant_id=$1 AND agent_id=$2 AND registration_id=$8",
            &[&identity.tenant_id, &identity.agent_id, &request.sequence, &now,
              &p.map(|p| p.deployment_sequence), &p.map(|p| p.revision.clone()), &p.map(|p| p.policy_sha256.clone()),
              &request.registration_id],
        ))
        .await?;
        self.bounded(tx.commit()).await?;
        Ok(Outcome::Accepted(()))
    }

    pub(in crate::tenant_store) async fn agent_heartbeat_status(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<HeartbeatStatus>> {
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
        let Some(enrollment) = self
            .bounded(tx.query_opt(
                "SELECT revoked_at_unix,credential_generation FROM managed_agent_enrollments WHERE tenant_id=$1 AND agent_id=$2",
                &[&tenant, &agent],
            ))
            .await?
        else {
            return Ok(None);
        };
        let (revoked, generation) = (
            enrollment.get::<_, Option<i64>>(0).is_some(),
            enrollment.get::<_, i64>(1),
        );
        let available: bool = self.bounded(tx.query_one(AVAILABLE, &[])).await?.get(0);
        let current = if available {
            self.bounded(tx.query_opt(
                &format!("SELECT {POSTGRES_ROW_COLUMNS} FROM agent_observations.heartbeats WHERE tenant_id=$1 AND agent_id=$2"),
                &[&tenant, &agent],
            ))
            .await?
            .map(|r| row(&r))
        } else {
            None
        };
        self.bounded(tx.commit()).await?;
        Ok(Some(agent_heartbeat::status(
            tenant,
            agent,
            revoked,
            generation,
            current,
            available,
            now_unix(),
        )))
    }

    /// Run by `migrate` with the migration role; idempotent and versionless
    /// so the accepted public-schema migrations stay exactly 1 through 28.
    pub(in crate::tenant_store) async fn migrate_agent_heartbeats(&self) -> Result<()> {
        let client = self.checkout().await?;
        self.bounded(client.batch_execute(agent_heartbeat::POSTGRES_SCHEMA))
            .await?;
        Ok(())
    }
}
