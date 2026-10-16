// SPDX-License-Identifier: Apache-2.0
//! SOU-30 SQLite Console issuer for approved, signed AgentPolicySet revisions.
//! Deliberately distinct from the Gateway TenantPolicyDocument API.

use anyhow::{ensure, Context, Result};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soup_wall_agent::AgentPolicySet;

use super::{now_unix, TenantStore};

const DOMAIN: &[u8] = b"soup-wall-agent-policy-bundle-v1\0";
pub(super) const MAX_YAML: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManagedBundle {
    pub schema_version: u16,
    pub tenant_id: String,
    pub agent_id: String,
    pub revision: String,
    pub deployment_sequence: u64,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub issuer_key_id: String,
    pub policy_yaml: String,
    pub policy_sha256: String,
    pub signature_hex: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ManagedRevision {
    pub tenant_id: String,
    pub agent_id: String,
    pub revision: String,
    pub policy_sha256: String,
    pub approved: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ManagedDeployment {
    pub tenant_id: String,
    pub agent_id: String,
    pub deployment_sequence: u64,
    pub revision: String,
    pub policy_sha256: String,
    pub action: String,
    pub status: String,
    pub issued_at_unix: i64,
    pub applied_at_unix: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedReport {
    pub deployment_sequence: u64,
    pub revision: String,
    pub policy_sha256: String,
    pub status: String,
}

pub struct ManagedIssuer {
    pub(super) key_id: String,
    pair: Ed25519KeyPair,
}

pub(super) fn exact_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_seed(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.is_ascii(),
        "expected 64 lowercase hex characters"
    );
    let mut out = [0u8; 32];
    for (idx, b) in out.iter_mut().enumerate() {
        let chunk = &value[idx * 2..idx * 2 + 2];
        ensure!(
            chunk
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "non-canonical issuer seed"
        );
        *b = u8::from_str_radix(chunk, 16)?;
    }
    Ok(out)
}
fn field(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len: u32 = value.len().try_into()?;
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(value);
    Ok(())
}
impl SignedManagedBundle {
    fn transcript(&self) -> Result<Vec<u8>> {
        let mut b = DOMAIN.to_vec();
        for v in [
            self.schema_version.to_string(),
            self.tenant_id.clone(),
            self.agent_id.clone(),
            self.revision.clone(),
            self.deployment_sequence.to_string(),
            self.issued_at_unix.to_string(),
            self.expires_at_unix.to_string(),
            self.issuer_key_id.clone(),
            self.policy_yaml.clone(),
            self.policy_sha256.clone(),
        ] {
            field(&mut b, v.as_bytes())?;
        }
        Ok(b)
    }
}
impl ManagedIssuer {
    pub fn new(key_id: String, seed_hex: &str) -> Result<Self> {
        ensure!(exact_id(&key_id), "invalid managed policy key ID");
        let pair = Ed25519KeyPair::from_seed_unchecked(&decode_seed(seed_hex)?)
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 issuer seed"))?;
        Ok(Self { key_id, pair })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The signing seed must come only from the operator environment; never
    /// from a request, bundle, tenant settings, or database row.
    pub fn from_environment() -> Result<Self> {
        Self::from_environment_for_key(None)
    }

    /// Load an issuer for an optionally specified key_id. If key_id is None or matches
    /// SOUP_AGENT_POLICY_KEY_ID, uses SOUP_AGENT_POLICY_SEED_HEX. Otherwise, checks
    /// SOUP_AGENT_POLICY_SEED_HEX_<KEY_ID> from the operator environment.
    pub fn from_environment_for_key(key_id: Option<&str>) -> Result<Self> {
        let default_key_id = std::env::var("SOUP_AGENT_POLICY_KEY_ID").ok();
        let target_key = match key_id {
            Some(k) => k,
            None => default_key_id
                .as_deref()
                .context("SOUP_AGENT_POLICY_KEY_ID required to sign deployments")?,
        };
        ensure!(exact_id(target_key), "invalid managed policy key ID");

        if default_key_id.as_deref() == Some(target_key) {
            let seed = std::env::var("SOUP_AGENT_POLICY_SEED_HEX")
                .context("SOUP_AGENT_POLICY_SEED_HEX required to sign deployments")?;
            return Self::new(target_key.to_string(), &seed);
        }

        let normalized: String = target_key
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        let env_var_name = format!("SOUP_AGENT_POLICY_SEED_HEX_{}", normalized);
        if let Ok(seed) = std::env::var(&env_var_name) {
            return Self::new(target_key.to_string(), &seed);
        }
        let literal_var = format!("SOUP_AGENT_POLICY_SEED_HEX_{}", target_key);
        if let Ok(seed) = std::env::var(&literal_var) {
            return Self::new(target_key.to_string(), &seed);
        }

        anyhow::bail!(
            "signing seed for issuer key '{}' not found in operator environment (checked {})",
            target_key,
            env_var_name
        );
    }

    pub fn public_key_hex(&self) -> String {
        hex(self.pair.public_key().as_ref())
    }
    pub(super) fn sign(&self, bundle: &mut SignedManagedBundle) -> Result<()> {
        bundle.signature_hex = hex(self.pair.sign(&bundle.transcript()?).as_ref());
        Ok(())
    }
}

fn schema(db: &rusqlite::Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS managed_agent_revisions (
           tenant_id TEXT NOT NULL,
           agent_id TEXT NOT NULL,
           revision TEXT NOT NULL,
           policy_yaml TEXT NOT NULL,
           policy_sha256 TEXT NOT NULL,
           approved_at_unix INTEGER,
           PRIMARY KEY(tenant_id, agent_id, revision),
           FOREIGN KEY(tenant_id, agent_id) REFERENCES managed_agent_enrollments(tenant_id,agent_id)
        );
        CREATE TABLE IF NOT EXISTS managed_agent_deployments (
           tenant_id TEXT NOT NULL,
           agent_id TEXT NOT NULL,
           deployment_sequence INTEGER NOT NULL CHECK(deployment_sequence > 0),
           revision TEXT NOT NULL,
           policy_sha256 TEXT NOT NULL,
           action TEXT NOT NULL CHECK(action IN ('activate','rollback')),
           bundle_json TEXT NOT NULL,
           status TEXT NOT NULL CHECK(status IN ('issued','delivered','applied','rejected')),
           issued_at_unix INTEGER NOT NULL,
           applied_at_unix INTEGER,
           PRIMARY KEY(tenant_id,agent_id,deployment_sequence),
           FOREIGN KEY(tenant_id,agent_id,revision)
             REFERENCES managed_agent_revisions(tenant_id,agent_id,revision)
        );",
    )
    .context("cannot prepare managed policy tables")
}

fn eligible(db: &rusqlite::Connection, tenant: &str, agent: &str) -> Result<()> {
    ensure!(
        exact_id(tenant) && exact_id(agent),
        "invalid policy audience"
    );
    let exists: Option<i64> = db
        .query_row(
            "SELECT 1 FROM managed_agent_enrollments a JOIN tenants t ON t.id=a.tenant_id
         WHERE a.tenant_id=?1 AND a.agent_id=?2 AND a.revoked_at_unix IS NULL AND t.active=1",
            params![tenant, agent],
            |r| r.get(0),
        )
        .optional()?;
    ensure!(exists.is_some(), "Agent not enrolled or revoked");
    Ok(())
}

impl TenantStore {
    pub fn create_managed_revision(
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
        let db = self.connection()?;
        schema(&db)?;
        eligible(&db, tenant, agent)?;
        db.execute(
            "INSERT INTO managed_agent_revisions
              (tenant_id,agent_id,revision,policy_yaml,policy_sha256)
             VALUES (?1,?2,?3,?4,?5)",
            params![tenant, agent, revision, yaml, digest],
        )
        .context("revision exists or cannot be created")?;
        Ok(ManagedRevision {
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            revision: revision.into(),
            policy_sha256: digest,
            approved: false,
        })
    }
    pub fn approve_managed_revision(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
    ) -> Result<bool> {
        let db = self.connection()?;
        schema(&db)?;
        eligible(&db, tenant, agent)?;
        let changed = db.execute(
            "UPDATE managed_agent_revisions SET approved_at_unix=?4
             WHERE tenant_id=?1 AND agent_id=?2 AND revision=?3 AND approved_at_unix IS NULL",
            params![tenant, agent, revision, now_unix()],
        )?;
        Ok(changed == 1)
    }
    /// New signed, monotonically numbered deployment. Rollback reuses only
    /// the APPROVED YAML payload, never the old signed envelope/sequence.
    pub fn deploy_managed_revision(
        &self,
        tenant: &str,
        agent: &str,
        revision: &str,
        rollback: bool,
        issuer: &ManagedIssuer,
    ) -> Result<ManagedDeployment> {
        let mut db = self.connection()?;
        schema(&db)?;
        let tx = db.transaction()?;
        eligible(&tx, tenant, agent)?;
        let payload: Option<(String, String)> = tx
            .query_row(
                "SELECT policy_yaml,policy_sha256 FROM managed_agent_revisions
             WHERE tenant_id=?1 AND agent_id=?2 AND revision=?3 AND approved_at_unix IS NOT NULL",
                params![tenant, agent, revision],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (yaml, digest) = payload.context("revision not approved or not found")?;
        let last: Option<(i64, String)> = tx
            .query_row(
                "SELECT deployment_sequence,revision FROM managed_agent_deployments
             WHERE tenant_id=?1 AND agent_id=?2 ORDER BY deployment_sequence DESC LIMIT 1",
                params![tenant, agent],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if rollback {
            let (_, previous) = last
                .as_ref()
                .context("cannot rollback with no prior deployment")?;
            ensure!(
                previous != revision,
                "rollback must select a different approved revision"
            );
        }
        let seq = last
            .map(|(s, _)| s)
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
            policy_yaml: yaml,
            policy_sha256: digest.clone(),
            signature_hex: String::new(),
        };
        issuer.sign(&mut bundle)?;
        tx.execute(
            "INSERT INTO managed_agent_deployments
             (tenant_id,agent_id,deployment_sequence,revision,policy_sha256,action,
              bundle_json,status,issued_at_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'issued',?8)",
            params![
                tenant,
                agent,
                seq,
                revision,
                digest,
                if rollback { "rollback" } else { "activate" },
                serde_json::to_string(&bundle)?,
                issued
            ],
        )?;
        tx.commit()?;
        Ok(ManagedDeployment {
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            deployment_sequence: seq.try_into()?,
            revision: revision.into(),
            policy_sha256: digest,
            action: if rollback {
                "rollback".into()
            } else {
                "activate".into()
            },
            status: "issued".into(),
            issued_at_unix: issued,
            applied_at_unix: None,
        })
    }
    fn require_managed_credential(
        db: &rusqlite::Connection, tenant: &str, agent: &str, bearer: &str,
    ) -> Result<()> {
        let token = bearer.strip_prefix("Bearer ").context("invalid Agent authorization")?;
        let hash = super::agent_enrollment::credential_hash(token)
            .context("invalid Agent credential")?;
        let authorized: Option<i64> = db.query_row(
            "SELECT 1 FROM managed_agent_enrollments
             WHERE tenant_id=?1 AND agent_id=?2 AND token_hash=?3 AND revoked_at_unix IS NULL",
            params![tenant,agent,hash], |r| r.get(0),
        ).optional()?;
        ensure!(authorized.is_some(), "Agent credential retired or revoked");
        Ok(())
    }

    pub fn deliver_authorized_managed_bundle(
        &self, tenant: &str, agent: &str, bearer: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        self.deliver_managed_bundle_inner(tenant,agent,Some(bearer))
    }

    pub fn deliver_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        self.deliver_managed_bundle_inner(tenant, agent, None)
    }
    fn deliver_managed_bundle_inner(
        &self, tenant: &str, agent: &str, credential: Option<&str>,
    ) -> Result<Option<SignedManagedBundle>> {
        let mut db = self.connection()?;
        schema(&db)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        eligible(&tx, tenant, agent)?;
        if let Some(bearer) = credential {
            Self::require_managed_credential(&tx, tenant, agent, bearer)?;
        }
        let latest: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT deployment_sequence,bundle_json,status
             FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2
             ORDER BY deployment_sequence DESC LIMIT 1",
                params![tenant, agent],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((sequence, json, status)) = latest else {
            return Ok(None);
        };
        if status == "applied" || status == "rejected" {
            return Ok(None);
        }
        let bundle: SignedManagedBundle = serde_json::from_str(&json)?;
        if now_unix() >= bundle.expires_at_unix {
            return Ok(None);
        }
        tx.execute(
            "UPDATE managed_agent_deployments SET status='delivered'
             WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence=?3 AND status='issued'",
            params![tenant, agent, sequence],
        )?;
        tx.commit()?;
        Ok(Some(bundle))
    }
    pub fn acknowledge_authorized_managed_bundle(
        &self, tenant: &str, agent: &str, bearer: &str, report: &AppliedReport,
    ) -> Result<bool> {
        self.acknowledge_managed_bundle_inner(tenant,agent,Some(bearer),report)
    }
    pub fn acknowledge_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        report: &AppliedReport,
    ) -> Result<bool> {
        self.acknowledge_managed_bundle_inner(tenant,agent,None,report)
    }
    fn acknowledge_managed_bundle_inner(
        &self, tenant: &str, agent: &str, credential: Option<&str>, report: &AppliedReport,
    ) -> Result<bool> {
        ensure!(
            report.status == "applied" || report.status == "rejected",
            "invalid acknowledgement"
        );
        let mut db = self.connection()?;
        schema(&db)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        eligible(&tx, tenant, agent)?;
        if let Some(bearer) = credential {
            Self::require_managed_credential(&tx, tenant, agent, bearer)?;
        }
        let seq: i64 = report.deployment_sequence.try_into()?;
        // A stale/unknown ack, including an ack for a superseded deployment,
        // may never mark the Console's current revision applied.
        let changed = tx.execute(
            "UPDATE managed_agent_deployments SET status=?4, applied_at_unix=
               CASE WHEN ?4='applied' THEN ?5 ELSE NULL END
             WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence=?3
               AND revision=?6 AND policy_sha256=?7
               AND status IN ('issued','delivered')
               AND deployment_sequence=(
                 SELECT MAX(deployment_sequence) FROM managed_agent_deployments
                 WHERE tenant_id=?1 AND agent_id=?2
               )",
            params![
                tenant,
                agent,
                seq,
                report.status,
                now_unix(),
                report.revision,
                report.policy_sha256
            ],
        )?;
        if changed == 1 {
            tx.commit()?;
            return Ok(true);
        }
        let repeated: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2
             AND deployment_sequence=?3 AND revision=?4 AND policy_sha256=?5 AND status=?6
             AND deployment_sequence=(SELECT MAX(deployment_sequence) FROM managed_agent_deployments
                                      WHERE tenant_id=?1 AND agent_id=?2)",
                params![
                    tenant,
                    agent,
                    seq,
                    report.revision,
                    report.policy_sha256,
                    report.status
                ],
                |r| r.get(0),
            )
            .optional()?;
        tx.commit()?;
        Ok(repeated.is_some())
    }
    pub fn list_managed_deployments(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Vec<ManagedDeployment>> {
        let db = self.connection()?;
        schema(&db)?;
        ensure!(exact_id(tenant) && exact_id(agent), "invalid identity");
        let mut stmt = db.prepare(
            "SELECT deployment_sequence,revision,policy_sha256,action,status,
                    issued_at_unix,applied_at_unix
             FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2
             ORDER BY deployment_sequence DESC LIMIT 50",
        )?;
        let rows = stmt.query_map(params![tenant, agent], |r| {
            let sequence: i64 = r.get(0)?;
            Ok(ManagedDeployment {
                tenant_id: tenant.into(),
                agent_id: agent.into(),
                deployment_sequence: sequence as u64,
                revision: r.get(1)?,
                policy_sha256: r.get(2)?,
                action: r.get(3)?,
                status: r.get(4)?,
                issued_at_unix: r.get(5)?,
                applied_at_unix: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};

    #[tokio::test]
    async fn managed_async_ack_retry_is_idempotent_but_stale_or_conflicting_is_refused() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("retry-test").unwrap();
        let issued = store
            .enroll_managed_agent_async(&tenant.id, "agent-a")
            .await
            .unwrap();
        let bearer = format!("Bearer {}", issued.token);
        assert!(store
            .authenticate_managed_agent_async(Some(&bearer))
            .await
            .unwrap()
            .is_some());
        let signer = ManagedIssuer {
            key_id: "k1".into(),
            pair: Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap(),
        };
        store
            .create_managed_revision_async(&tenant.id, "agent-a", "v1", "default: deny\n")
            .await
            .unwrap();
        store
            .approve_managed_revision_async(&tenant.id, "agent-a", "v1")
            .await
            .unwrap();
        store
            .deploy_managed_revision_async(&tenant.id, "agent-a", "v1", false, &signer)
            .await
            .unwrap();
        let bundle = store
            .deliver_managed_bundle_async(&tenant.id, "agent-a")
            .await
            .unwrap()
            .unwrap();
        let repeated = store
            .deliver_managed_bundle_async(&tenant.id, "agent-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&bundle).unwrap(),
            serde_json::to_value(&repeated).unwrap()
        );
        let mut report = AppliedReport {
            deployment_sequence: 1,
            revision: "v1".into(),
            policy_sha256: bundle.policy_sha256,
            status: "applied".into(),
        };
        assert!(store
            .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
            .await
            .unwrap());
        let before = store
            .list_managed_deployments_async(&tenant.id, "agent-a")
            .await
            .unwrap();
        assert!(store
            .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
            .await
            .unwrap());
        let after = store
            .list_managed_deployments_async(&tenant.id, "agent-a")
            .await
            .unwrap();
        assert_eq!(before[0].applied_at_unix, after[0].applied_at_unix);
        report.status = "rejected".into();
        assert!(!store
            .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
            .await
            .unwrap());
        assert!(store
            .deliver_managed_bundle_async(&tenant.id, "agent-a")
            .await
            .unwrap()
            .is_none());
        store
            .deploy_managed_revision_async(&tenant.id, "agent-a", "v1", false, &signer)
            .await
            .unwrap();
        report.status = "applied".into();
        assert!(!store
            .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
            .await
            .unwrap());
        report.deployment_sequence = 2;
        report.status = "rejected".into();
        assert!(store
            .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
            .await
            .unwrap());
        assert!(store
            .acknowledge_managed_bundle_async(&tenant.id, "agent-a", &report)
            .await
            .unwrap());
        assert!(store
            .revoke_managed_agent_async(&tenant.id, "agent-a")
            .await
            .unwrap());
        assert!(store
            .authenticate_managed_agent_async(Some(&bearer))
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn approved_deployment_is_signed_and_rollback_increases_sequence() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("managed-issuer-test").unwrap();
        store.enroll_managed_agent(&tenant.id, "agent-a").unwrap();
        store
            .create_managed_revision(&tenant.id, "agent-a", "v1", "default: deny\n")
            .unwrap();
        store
            .create_managed_revision(&tenant.id, "agent-a", "v2", "default: allow\n")
            .unwrap();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
        let signer = ManagedIssuer {
            key_id: "k1".into(),
            pair,
        };
        assert!(store
            .deploy_managed_revision(&tenant.id, "agent-a", "v1", false, &signer)
            .is_err());
        assert!(store
            .approve_managed_revision(&tenant.id, "agent-a", "v1")
            .unwrap());
        assert!(store
            .approve_managed_revision(&tenant.id, "agent-a", "v2")
            .unwrap());
        let a = store
            .deploy_managed_revision(&tenant.id, "agent-a", "v1", false, &signer)
            .unwrap();
        assert_eq!(a.deployment_sequence, 1);
        let b = store
            .deliver_managed_bundle(&tenant.id, "agent-a")
            .unwrap()
            .unwrap();
        let signature = hex(signer.pair.sign(&b.transcript().unwrap()).as_ref());
        assert_eq!(signature, b.signature_hex);
        assert!(
            UnparsedPublicKey::new(&ED25519, signer.pair.public_key().as_ref())
                .verify(&b.transcript().unwrap(), &{
                    let mut bytes = [0u8; 64];
                    for (i, chunk) in b
                        .signature_hex
                        .as_bytes()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .enumerate()
                    {
                        bytes[i] =
                            u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap()
                    }
                    bytes
                })
                .is_ok()
        );
        assert!(store
            .acknowledge_managed_bundle(
                &tenant.id,
                "agent-a",
                &AppliedReport {
                    deployment_sequence: 1,
                    revision: "v1".into(),
                    policy_sha256: b.policy_sha256.clone(),
                    status: "applied".into()
                }
            )
            .unwrap());
        store
            .deploy_managed_revision(&tenant.id, "agent-a", "v2", false, &signer)
            .unwrap();
        let r = store
            .deploy_managed_revision(&tenant.id, "agent-a", "v1", true, &signer)
            .unwrap();
        assert_eq!(r.deployment_sequence, 3);
        assert_eq!(r.action, "rollback");
        assert!(!store
            .acknowledge_managed_bundle(
                &tenant.id,
                "agent-a",
                &AppliedReport {
                    deployment_sequence: 1,
                    revision: "v1".into(),
                    policy_sha256: b.policy_sha256,
                    status: "applied".into()
                }
            )
            .unwrap());
        assert_eq!(
            store
                .list_managed_deployments(&tenant.id, "agent-a")
                .unwrap()
                .len(),
            3
        );
    }
}
