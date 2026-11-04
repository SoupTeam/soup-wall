// SPDX-License-Identifier: Apache-2.0
//! SOU-219: optional idempotency key for the individual managed-deployment issuance.
//!
//! The key is persisted in the same storage transaction as the issuance it protects, so a
//! committed issuance always has its key and an uncommitted one has neither. A key is bound to
//! tenant, Agent, the authenticated admin and the canonical deployment intent. It never grants
//! authority: every retry re-checks the Agent, tenant and admin before a stored result is returned.
use anyhow::{ensure, Context, Result};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

use super::managed_policy::{
    eligible, exact_id, hex, schema, DeploymentMode, ManagedDeployment, SignedManagedBundle,
};
use super::{AdminRole, ManagedIssuer, TenantStore};

pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MIN_IDEMPOTENCY_KEY_BYTES: usize = 8;
/// Identity the bootstrap admin token authenticates as; it has no stored row to recheck.
const BOOTSTRAP_ADMIN: &str = "bootstrap_owner";
const INTENT_DOMAIN: &[u8] = b"soup-wall-managed-deployment-intent-v1\0";

pub fn valid_idempotency_key(key: &str) -> bool {
    (MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

/// The caller-supplied key plus the authenticated principal that presented it.
#[derive(Clone, Copy, Debug)]
pub struct DeploymentIdempotency<'a> {
    pub key: &'a str,
    pub admin_id: &'a str,
    /// The `issuer_key_id` exactly as requested (`None` when the default signer was meant).
    pub requested_issuer_key: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct KeyedDeployment {
    pub deployment: ManagedDeployment,
    pub replayed: bool,
    pub envelope_sha256: String,
    pub expires_at_unix: i64,
    pub issuer_key_id: String,
}

/// The key was already used by another principal or for a different deployment intent.
#[derive(Debug)]
pub struct IdempotencyConflict;
impl std::fmt::Display for IdempotencyConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("idempotency key conflicts with a previous request")
    }
}
impl std::error::Error for IdempotencyConflict {}

/// Canonical digest of the deployment intent: what the key promises will be issued.
pub(super) fn intent_digest(
    idem: &DeploymentIdempotency<'_>,
    revision: &str,
    policy_sha256: &str,
    mode: DeploymentMode,
) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(INTENT_DOMAIN);
    let action = if mode == DeploymentMode::Activate {
        "activate"
    } else {
        "rollback"
    };
    for part in [
        idem.admin_id,
        idem.requested_issuer_key.unwrap_or(""),
        revision,
        policy_sha256,
        action,
    ] {
        digest.update((part.len() as u32).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().to_vec()
}

pub(super) fn keyed_result(
    deployment: ManagedDeployment,
    bundle_json: &str,
    replayed: bool,
) -> Result<KeyedDeployment> {
    let bundle: SignedManagedBundle = serde_json::from_str(bundle_json)?;
    Ok(KeyedDeployment {
        deployment,
        replayed,
        envelope_sha256: hex(&Sha256::digest(bundle_json.as_bytes())),
        expires_at_unix: bundle.expires_at_unix,
        issuer_key_id: bundle.issuer_key_id,
    })
}

pub(super) fn ensure_key_shape(idem: &DeploymentIdempotency<'_>) -> Result<()> {
    ensure!(valid_idempotency_key(idem.key), "invalid idempotency key");
    ensure!(
        exact_id(idem.admin_id),
        "invalid authenticated administrator"
    );
    Ok(())
}

impl TenantStore {
    /// Keyed issuance: an exact retry returns the original issuance and never signs, numbers or
    /// dispatches again. A missing signer only matters when a new issuance is needed.
    pub fn deploy_managed_revision_keyed(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
        rollback: bool,
        issuer: Option<&ManagedIssuer>,
        idem: &DeploymentIdempotency<'_>,
    ) -> Result<KeyedDeployment> {
        ensure_key_shape(idem)?;
        let mut db = self.connection()?;
        schema(&db)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mode = if rollback {
            DeploymentMode::Rollback
        } else {
            DeploymentMode::Activate
        };
        // Authorization is evaluated against current state before any stored result is consulted.
        eligible(&tx, tenant, agent)?;
        current_admin_may_deploy(&tx, idem.admin_id)?;
        let digest: String = tx
            .query_row(
                "SELECT policy_sha256 FROM managed_agent_revisions
                 WHERE tenant_id=?1 AND agent_id=?2 AND revision=?3 AND approved_at_unix IS NOT NULL",
                params![tenant, agent, revision],
                |r| r.get(0),
            )
            .optional()?
            .context("revision not approved or not found")?;
        let intent = intent_digest(idem, revision, &digest, mode);
        let existing: Option<(String, Vec<u8>, i64)> = tx
            .query_row(
                "SELECT admin_id,intent_digest,deployment_sequence FROM managed_agent_deployment_keys
                 WHERE tenant_id=?1 AND agent_id=?2 AND idempotency_key=?3",
                params![tenant, agent, idem.key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((admin, stored_intent, sequence)) = existing {
            ensure!(
                admin == idem.admin_id && stored_intent == intent,
                IdempotencyConflict
            );
            let result = load_issuance(&tx, tenant, agent, sequence)?;
            tx.commit()?;
            return Ok(result);
        }
        let issuer = issuer.context("Agent policy issuer unavailable")?;
        let deployment =
            self.deploy_managed_revision_conn(&tx, tenant, agent, revision, mode, issuer)?;
        tx.execute(
            "INSERT INTO managed_agent_deployment_keys
             (tenant_id,agent_id,idempotency_key,admin_id,intent_digest,deployment_sequence,created_at_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                tenant,
                agent,
                idem.key,
                idem.admin_id,
                intent,
                deployment.deployment_sequence as i64,
                deployment.issued_at_unix
            ],
        )?;
        let result = load_issuance(&tx, tenant, agent, deployment.deployment_sequence as i64).map(
            |mut r| {
                r.replayed = false;
                r
            },
        )?;
        tx.commit()?;
        Ok(result)
    }
}

fn load_issuance(
    db: &rusqlite::Connection,
    tenant: &str,
    agent: &str,
    sequence: i64,
) -> Result<KeyedDeployment> {
    let (deployment, bundle_json) = db.query_row(
        "SELECT revision,policy_sha256,action,status,issued_at_unix,applied_at_unix,bundle_json
         FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence=?3",
        params![tenant, agent, sequence],
        |r| {
            Ok((
                ManagedDeployment {
                    tenant_id: tenant.into(),
                    agent_id: agent.into(),
                    deployment_sequence: sequence as u64,
                    revision: r.get(0)?,
                    policy_sha256: r.get(1)?,
                    action: r.get(2)?,
                    status: r.get(3)?,
                    issued_at_unix: r.get(4)?,
                    applied_at_unix: r.get(5)?,
                },
                r.get::<_, String>(6)?,
            ))
        },
    )?;
    keyed_result(deployment, &bundle_json, true)
}

/// A stored administrator must still be active and permitted to mutate; the bootstrap owner has
/// no row. This repeats the request-time check (agent mutations require an owner) inside the
/// issuing transaction.
fn current_admin_may_deploy(db: &rusqlite::Connection, admin_id: &str) -> Result<()> {
    if admin_id == BOOTSTRAP_ADMIN {
        return Ok(());
    }
    let role: Option<String> = db
        .query_row(
            "SELECT role FROM control_plane_admins WHERE id=?1 AND active=1",
            params![admin_id],
            |r| r.get(0),
        )
        .optional()?;
    let role = role.context("administrator is no longer active")?;
    ensure!(
        AdminRole::from_storage(&role)?.permits(AdminRole::Owner),
        "administrator role does not permit deployment"
    );
    Ok(())
}

pub(super) const SQLITE_KEYS_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS managed_agent_deployment_keys (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
    admin_id TEXT NOT NULL,
    intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
    deployment_sequence INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,agent_id,idempotency_key),
    UNIQUE(tenant_id,agent_id,deployment_sequence),
    FOREIGN KEY(tenant_id,agent_id,deployment_sequence)
      REFERENCES managed_agent_deployments(tenant_id,agent_id,deployment_sequence)
);";
