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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedAgentGroup {
    pub tenant_id: String,
    pub group_id: String,
    pub name: String,
    pub created_at_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedGroupMember {
    pub tenant_id: String,
    pub group_id: String,
    pub agent_id: String,
    pub is_pilot: bool,
    pub joined_at_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedGroupRevision {
    pub tenant_id: String,
    pub group_id: String,
    pub revision: String,
    pub policy_sha256: String,
    pub approved: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    Pilot,
    Standard,
    Completed,
    RolledBack,
    Failed,
}

impl RolloutPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            RolloutPhase::Pilot => "pilot",
            RolloutPhase::Standard => "standard",
            RolloutPhase::Completed => "completed",
            RolloutPhase::RolledBack => "rolled_back",
            RolloutPhase::Failed => "failed",
        }
    }
}

impl std::str::FromStr for RolloutPhase {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pilot" => Ok(RolloutPhase::Pilot),
            "standard" => Ok(RolloutPhase::Standard),
            "completed" => Ok(RolloutPhase::Completed),
            "rolled_back" => Ok(RolloutPhase::RolledBack),
            "failed" => Ok(RolloutPhase::Failed),
            other => anyhow::bail!("unknown rollout phase: {}", other),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedGroupRollout {
    pub tenant_id: String,
    pub group_id: String,
    pub rollout_id: String,
    pub revision: String,
    pub policy_sha256: String,
    pub issuer_key_id: Option<String>,
    pub phase: RolloutPhase,
    pub pilot_agents: Vec<String>,
    pub standard_agents: Vec<String>,
    pub active_deployments: std::collections::BTreeMap<String, u64>,
    pub previous_revisions: std::collections::BTreeMap<String, Option<String>>,
    pub failure_reason: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
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
        );
        CREATE TABLE IF NOT EXISTS managed_agent_groups (
           tenant_id TEXT NOT NULL,
           group_id TEXT NOT NULL,
           name TEXT NOT NULL,
           created_at_unix INTEGER NOT NULL,
           PRIMARY KEY(tenant_id, group_id),
           FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS managed_agent_group_members (
           tenant_id TEXT NOT NULL,
           group_id TEXT NOT NULL,
           agent_id TEXT NOT NULL,
           is_pilot INTEGER NOT NULL DEFAULT 0,
           joined_at_unix INTEGER NOT NULL,
           PRIMARY KEY(tenant_id, group_id, agent_id),
           FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE,
           FOREIGN KEY(tenant_id, agent_id) REFERENCES managed_agent_enrollments(tenant_id, agent_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS managed_group_revisions (
           tenant_id TEXT NOT NULL,
           group_id TEXT NOT NULL,
           revision TEXT NOT NULL,
           policy_yaml TEXT NOT NULL,
           policy_sha256 TEXT NOT NULL,
           approved_at_unix INTEGER,
           PRIMARY KEY(tenant_id, group_id, revision),
           FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS managed_group_rollouts (
           tenant_id TEXT NOT NULL,
           group_id TEXT NOT NULL,
           rollout_id TEXT NOT NULL,
           revision TEXT NOT NULL,
           policy_sha256 TEXT NOT NULL,
           issuer_key_id TEXT,
           phase TEXT NOT NULL CHECK(phase IN ('pilot','standard','completed','rolled_back','failed')),
           pilot_agents_json TEXT NOT NULL,
           standard_agents_json TEXT NOT NULL,
           active_deployments_json TEXT NOT NULL,
           previous_revisions_json TEXT NOT NULL,
           failure_reason TEXT,
           created_at_unix INTEGER NOT NULL,
           updated_at_unix INTEGER NOT NULL,
           PRIMARY KEY(tenant_id, group_id, rollout_id),
           FOREIGN KEY(tenant_id, group_id) REFERENCES managed_agent_groups(tenant_id, group_id) ON DELETE CASCADE
        );",
    )
    .context("cannot prepare managed policy tables")
}

fn eligible_group(db: &rusqlite::Connection, tenant: &str, group: &str) -> Result<()> {
    ensure!(exact_id(tenant) && exact_id(group), "invalid group identity");
    let exists: Option<i64> = db
        .query_row(
            "SELECT 1 FROM managed_agent_groups g JOIN tenants t ON t.id=g.tenant_id
             WHERE g.tenant_id=?1 AND g.group_id=?2 AND t.active=1",
            params![tenant, group],
            |r| r.get(0),
        )
        .optional()?;
    ensure!(exists.is_some(), "group not found or tenant inactive");
    Ok(())
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
    pub fn deliver_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<SignedManagedBundle>> {
        let db = self.connection()?;
        schema(&db)?;
        eligible(&db, tenant, agent)?;
        let latest: Option<(i64, String, String)> = db
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
        db.execute(
            "UPDATE managed_agent_deployments SET status='delivered'
             WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence=?3 AND status='issued'",
            params![tenant, agent, sequence],
        )?;
        Ok(Some(bundle))
    }
    pub fn acknowledge_managed_bundle(
        &self,
        tenant: &str,
        agent: &str,
        report: &AppliedReport,
    ) -> Result<bool> {
        ensure!(
            report.status == "applied" || report.status == "rejected",
            "invalid acknowledgement"
        );
        let db = self.connection()?;
        schema(&db)?;
        eligible(&db, tenant, agent)?;
        let seq: i64 = report.deployment_sequence.try_into()?;
        // A stale/unknown ack, including an ack for a superseded deployment,
        // may never mark the Console's current revision applied.
        let changed = db.execute(
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
            drop(db);
            let _ = self.check_and_advance_active_rollouts_for_agent(tenant, agent);
            return Ok(true);
        }
        let repeated: Option<i64> = db
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

    pub fn create_managed_group(
        &self,
        tenant: &str,
        group_id: &str,
        name: &str,
    ) -> Result<ManagedAgentGroup> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid group identifier");
        ensure!(!name.is_empty() && name.len() <= 256, "invalid group name");
        let db = self.connection()?;
        schema(&db)?;
        let tenant_active: Option<i64> = db
            .query_row(
                "SELECT 1 FROM tenants WHERE id=?1 AND active=1",
                params![tenant],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(tenant_active.is_some(), "tenant not found or inactive");
        let now = now_unix();
        db.execute(
            "INSERT INTO managed_agent_groups (tenant_id, group_id, name, created_at_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![tenant, group_id, name, now],
        )
        .context("group already exists or cannot be created")?;
        Ok(ManagedAgentGroup {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            name: name.into(),
            created_at_unix: now,
        })
    }

    pub fn list_managed_groups(&self, tenant: &str) -> Result<Vec<ManagedAgentGroup>> {
        ensure!(exact_id(tenant), "invalid tenant identifier");
        let db = self.connection()?;
        schema(&db)?;
        let mut stmt = db.prepare(
            "SELECT group_id, name, created_at_unix FROM managed_agent_groups
             WHERE tenant_id=?1 ORDER BY created_at_unix ASC",
        )?;
        let rows = stmt.query_map(params![tenant], |r| {
            Ok(ManagedAgentGroup {
                tenant_id: tenant.into(),
                group_id: r.get(0)?,
                name: r.get(1)?,
                created_at_unix: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_managed_group(&self, tenant: &str, group_id: &str) -> Result<Option<ManagedAgentGroup>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let db = self.connection()?;
        schema(&db)?;
        let res = db
            .query_row(
                "SELECT name, created_at_unix FROM managed_agent_groups WHERE tenant_id=?1 AND group_id=?2",
                params![tenant, group_id],
                |r| {
                    Ok(ManagedAgentGroup {
                        tenant_id: tenant.into(),
                        group_id: group_id.into(),
                        name: r.get(0)?,
                        created_at_unix: r.get(1)?,
                    })
                },
            )
            .optional()?;
        Ok(res)
    }

    pub fn delete_managed_group(&self, tenant: &str, group_id: &str) -> Result<bool> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let db = self.connection()?;
        schema(&db)?;
        let active: Option<i64> = db
            .query_row(
                "SELECT 1 FROM managed_group_rollouts WHERE tenant_id=?1 AND group_id=?2 AND phase IN ('pilot','standard')",
                params![tenant, group_id],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(active.is_none(), "cannot delete group with active rollout in progress");
        let count = db.execute(
            "DELETE FROM managed_agent_groups WHERE tenant_id=?1 AND group_id=?2",
            params![tenant, group_id],
        )?;
        Ok(count > 0)
    }

    pub fn add_managed_group_member(
        &self,
        tenant: &str,
        group_id: &str,
        agent_id: &str,
        is_pilot: bool,
    ) -> Result<ManagedGroupMember> {
        let db = self.connection()?;
        schema(&db)?;
        eligible_group(&db, tenant, group_id)?;
        eligible(&db, tenant, agent_id)?;
        let now = now_unix();
        db.execute(
            "INSERT INTO managed_agent_group_members (tenant_id, group_id, agent_id, is_pilot, joined_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(tenant_id, group_id, agent_id) DO UPDATE SET is_pilot=excluded.is_pilot",
            params![tenant, group_id, agent_id, if is_pilot { 1 } else { 0 }, now],
        )?;
        Ok(ManagedGroupMember {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            agent_id: agent_id.into(),
            is_pilot,
            joined_at_unix: now,
        })
    }

    pub fn remove_managed_group_member(&self, tenant: &str, group_id: &str, agent_id: &str) -> Result<bool> {
        ensure!(exact_id(tenant) && exact_id(group_id) && exact_id(agent_id), "invalid identifier");
        let db = self.connection()?;
        schema(&db)?;
        let count = db.execute(
            "DELETE FROM managed_agent_group_members WHERE tenant_id=?1 AND group_id=?2 AND agent_id=?3",
            params![tenant, group_id, agent_id],
        )?;
        Ok(count > 0)
    }

    pub fn list_managed_group_members(&self, tenant: &str, group_id: &str) -> Result<Vec<ManagedGroupMember>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let db = self.connection()?;
        schema(&db)?;
        eligible_group(&db, tenant, group_id)?;
        let mut stmt = db.prepare(
            "SELECT agent_id, is_pilot, joined_at_unix FROM managed_agent_group_members
             WHERE tenant_id=?1 AND group_id=?2 ORDER BY is_pilot DESC, joined_at_unix ASC",
        )?;
        let rows = stmt.query_map(params![tenant, group_id], |r| {
            let is_pilot_num: i64 = r.get(1)?;
            Ok(ManagedGroupMember {
                tenant_id: tenant.into(),
                group_id: group_id.into(),
                agent_id: r.get(0)?,
                is_pilot: is_pilot_num == 1,
                joined_at_unix: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn create_managed_group_revision(
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
        let db = self.connection()?;
        schema(&db)?;
        eligible_group(&db, tenant, group_id)?;
        db.execute(
            "INSERT INTO managed_group_revisions (tenant_id, group_id, revision, policy_yaml, policy_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![tenant, group_id, revision, yaml, digest],
        )
        .context("group revision exists or cannot be created")?;
        Ok(ManagedGroupRevision {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            revision: revision.into(),
            policy_sha256: digest,
            approved: false,
        })
    }

    pub fn approve_managed_group_revision(&self, tenant: &str, group_id: &str, revision: &str) -> Result<bool> {
        let db = self.connection()?;
        schema(&db)?;
        eligible_group(&db, tenant, group_id)?;
        let changed = db.execute(
            "UPDATE managed_group_revisions SET approved_at_unix=?4
             WHERE tenant_id=?1 AND group_id=?2 AND revision=?3 AND approved_at_unix IS NULL",
            params![tenant, group_id, revision, now_unix()],
        )?;
        Ok(changed == 1)
    }

    pub fn list_managed_group_revisions(&self, tenant: &str, group_id: &str) -> Result<Vec<ManagedGroupRevision>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let db = self.connection()?;
        schema(&db)?;
        eligible_group(&db, tenant, group_id)?;
        let mut stmt = db.prepare(
            "SELECT revision, policy_sha256, approved_at_unix FROM managed_group_revisions
             WHERE tenant_id=?1 AND group_id=?2 ORDER BY revision ASC",
        )?;
        let rows = stmt.query_map(params![tenant, group_id], |r| {
            let approved: Option<i64> = r.get(2)?;
            Ok(ManagedGroupRevision {
                tenant_id: tenant.into(),
                group_id: group_id.into(),
                revision: r.get(0)?,
                policy_sha256: r.get(1)?,
                approved: approved.is_some(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn start_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        revision: &str,
        issuer: &ManagedIssuer,
    ) -> Result<ManagedGroupRollout> {
        let (_policy_yaml, policy_sha256, pilot_agents, standard_agents, previous_revisions) = {
            let db = self.connection()?;
            schema(&db)?;
            eligible_group(&db, tenant, group_id)?;

            let active: Option<String> = db
                .query_row(
                    "SELECT rollout_id FROM managed_group_rollouts
                 WHERE tenant_id=?1 AND group_id=?2 AND phase IN ('pilot','standard')",
                    params![tenant, group_id],
                    |r| r.get(0),
                )
                .optional()?;
            ensure!(
                active.is_none(),
                "active rollout already in progress for group '{}'",
                group_id
            );

            let rev_row: Option<(String, String)> = db
                .query_row(
                    "SELECT policy_yaml, policy_sha256 FROM managed_group_revisions
                 WHERE tenant_id=?1 AND group_id=?2 AND revision=?3 AND approved_at_unix IS NOT NULL",
                    params![tenant, group_id, revision],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (policy_yaml, policy_sha256) =
                rev_row.context("group revision not approved or not found")?;

            let mut stmt = db.prepare(
                "SELECT agent_id, is_pilot FROM managed_agent_group_members
                 WHERE tenant_id=?1 AND group_id=?2 ORDER BY is_pilot DESC, joined_at_unix ASC",
            )?;
            let member_rows = stmt
                .query_map(params![tenant, group_id], |r| {
                    let agent_id: String = r.get(0)?;
                    let is_pilot: i64 = r.get(1)?;
                    Ok((agent_id, is_pilot == 1))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(!member_rows.is_empty(), "cannot start rollout on empty group");

            let mut pilots = Vec::new();
            let mut standards = Vec::new();
            for (agent_id, is_pilot) in member_rows {
                if is_pilot {
                    pilots.push(agent_id);
                } else {
                    standards.push(agent_id);
                }
            }
            ensure!(
                !pilots.is_empty(),
                "group has no pilot agents for staged rollout"
            );

            let mut prevs = std::collections::BTreeMap::new();
            for pilot in &pilots {
                let prev: Option<String> = db
                    .query_row(
                        "SELECT revision FROM managed_agent_deployments
                     WHERE tenant_id=?1 AND agent_id=?2 ORDER BY deployment_sequence DESC LIMIT 1",
                        params![tenant, pilot],
                        |r| r.get(0),
                    )
                    .optional()?;
                prevs.insert(pilot.clone(), prev);
            }
            for std in &standards {
                let prev: Option<String> = db
                    .query_row(
                        "SELECT revision FROM managed_agent_deployments
                     WHERE tenant_id=?1 AND agent_id=?2 ORDER BY deployment_sequence DESC LIMIT 1",
                        params![tenant, std],
                        |r| r.get(0),
                    )
                    .optional()?;
                prevs.insert(std.clone(), prev);
            }

            for pilot in &pilots {
                let exists: Option<i64> = db
                    .query_row(
                        "SELECT 1 FROM managed_agent_revisions WHERE tenant_id=?1 AND agent_id=?2 AND revision=?3",
                        params![tenant, pilot, revision],
                        |r| r.get(0),
                    )
                    .optional()?;
                if exists.is_none() {
                    db.execute(
                        "INSERT INTO managed_agent_revisions (tenant_id, agent_id, revision, policy_yaml, policy_sha256, approved_at_unix)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![tenant, pilot, revision, policy_yaml, policy_sha256, now_unix()],
                    )?;
                }
            }

            (policy_yaml, policy_sha256, pilots, standards, prevs)
        };

        let mut active_deployments = std::collections::BTreeMap::new();
        for pilot in &pilot_agents {
            let dep = self.deploy_managed_revision(tenant, pilot, revision, false, issuer)?;
            active_deployments.insert(pilot.clone(), dep.deployment_sequence);
        }

        let rollout_id = format!("ro_{}", super::random_base64url(12));
        let now = now_unix();
        let phase = RolloutPhase::Pilot;

        {
            let db = self.connection()?;
            db.execute(
                "INSERT INTO managed_group_rollouts
                 (tenant_id, group_id, rollout_id, revision, policy_sha256, issuer_key_id, phase,
                  pilot_agents_json, standard_agents_json, active_deployments_json, previous_revisions_json,
                  failure_reason, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?12)",
                params![
                    tenant,
                    group_id,
                    rollout_id,
                    revision,
                    policy_sha256,
                    issuer.key_id(),
                    phase.as_str(),
                    serde_json::to_string(&pilot_agents)?,
                    serde_json::to_string(&standard_agents)?,
                    serde_json::to_string(&active_deployments)?,
                    serde_json::to_string(&previous_revisions)?,
                    now,
                ],
            )?;
        }

        Ok(ManagedGroupRollout {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            rollout_id,
            revision: revision.into(),
            policy_sha256,
            issuer_key_id: Some(issuer.key_id().into()),
            phase,
            pilot_agents,
            standard_agents,
            active_deployments,
            previous_revisions,
            failure_reason: None,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    pub fn advance_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        enum NextAction {
            None,
            StillRunning(ManagedGroupRollout),
            Rollback {
                rollout: ManagedGroupRollout,
                to_rollback: Vec<(String, String)>,
                reason: String,
            },
            PromoteToStandard {
                rollout: ManagedGroupRollout,
                standards: Vec<String>,
                revision: String,
            },
            Complete(ManagedGroupRollout),
        }

        let action = {
            let db = self.connection()?;
            schema(&db)?;
            let row: Option<(
                String,
                String,
                String,
                Option<String>,
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                i64,
                i64,
            )> = db
                .query_row(
                    "SELECT rollout_id, revision, policy_sha256, issuer_key_id, phase,
                        pilot_agents_json, standard_agents_json, active_deployments_json,
                        previous_revisions_json, failure_reason, created_at_unix, updated_at_unix
                 FROM managed_group_rollouts
                 WHERE tenant_id=?1 AND group_id=?2 AND phase IN ('pilot','standard')
                 ORDER BY created_at_unix DESC LIMIT 1",
                    params![tenant, group_id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                            r.get(9)?,
                            r.get(10)?,
                            r.get(11)?,
                        ))
                    },
                )
                .optional()?;

            let Some((
                rollout_id,
                revision,
                policy_sha256,
                issuer_key_id,
                phase_str,
                pilot_json,
                standard_json,
                active_json,
                prev_json,
                failure_reason,
                created_at,
                updated_at,
            )) = row
            else {
                return Ok(None);
            };

            let current_phase: RolloutPhase = phase_str.parse()?;
            let pilot_agents: Vec<String> = serde_json::from_str(&pilot_json)?;
            let standard_agents: Vec<String> = serde_json::from_str(&standard_json)?;
            let active_deployments: std::collections::BTreeMap<String, u64> =
                serde_json::from_str(&active_json)?;
            let previous_revisions: std::collections::BTreeMap<String, Option<String>> =
                serde_json::from_str(&prev_json)?;

            let yaml: String = db.query_row(
                "SELECT policy_yaml FROM managed_group_revisions WHERE tenant_id=?1 AND group_id=?2 AND revision=?3",
                params![tenant, group_id, revision],
                |r| r.get(0),
            )?;

            let base_rollout = ManagedGroupRollout {
                tenant_id: tenant.into(),
                group_id: group_id.into(),
                rollout_id,
                revision: revision.clone(),
                policy_sha256: policy_sha256.clone(),
                issuer_key_id,
                phase: current_phase,
                pilot_agents: pilot_agents.clone(),
                standard_agents: standard_agents.clone(),
                active_deployments: active_deployments.clone(),
                previous_revisions: previous_revisions.clone(),
                failure_reason,
                created_at_unix: created_at,
                updated_at_unix: updated_at,
            };

            match current_phase {
                RolloutPhase::Pilot => {
                    let mut any_rejected = None;
                    let mut all_applied = true;
                    for p in &pilot_agents {
                        let seq = match active_deployments.get(p) {
                            Some(&s) => s,
                            None => {
                                all_applied = false;
                                continue;
                            }
                        };
                        let st: Option<String> = db
                            .query_row(
                                "SELECT status FROM managed_agent_deployments
                             WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence=?3",
                                params![tenant, p, seq as i64],
                                |r| r.get(0),
                            )
                            .optional()?;
                        match st.as_deref() {
                            Some("rejected") => {
                                any_rejected = Some(p.clone());
                                break;
                            }
                            Some("applied") => {}
                            _ => {
                                all_applied = false;
                            }
                        }
                    }

                    if let Some(rejected_agent) = any_rejected {
                        let reason = format!(
                            "pilot agent '{}' rejected candidate policy revision '{}'",
                            rejected_agent, revision
                        );
                        let mut to_rollback = Vec::new();
                        for (agent, _) in &active_deployments {
                            if let Some(Some(prev)) = previous_revisions.get(agent) {
                                to_rollback.push((agent.clone(), prev.clone()));
                            }
                        }
                        NextAction::Rollback {
                            rollout: base_rollout,
                            to_rollback,
                            reason,
                        }
                    } else if all_applied {
                        if standard_agents.is_empty() {
                            NextAction::Complete(base_rollout)
                        } else {
                            for w in &standard_agents {
                                let exists: Option<i64> = db
                                    .query_row(
                                        "SELECT 1 FROM managed_agent_revisions WHERE tenant_id=?1 AND agent_id=?2 AND revision=?3",
                                        params![tenant, w, revision],
                                        |r| r.get(0),
                                    )
                                    .optional()?;
                                if exists.is_none() {
                                    db.execute(
                                        "INSERT INTO managed_agent_revisions (tenant_id, agent_id, revision, policy_yaml, policy_sha256, approved_at_unix)
                                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                        params![tenant, w, revision, yaml, policy_sha256, now_unix()],
                                    )?;
                                }
                            }
                            NextAction::PromoteToStandard {
                                rollout: base_rollout,
                                standards: standard_agents,
                                revision,
                            }
                        }
                    } else {
                        NextAction::StillRunning(base_rollout)
                    }
                }
                RolloutPhase::Standard => {
                    let mut any_rejected = None;
                    let mut all_applied = true;
                    for w in &standard_agents {
                        let seq = match active_deployments.get(w) {
                            Some(&s) => s,
                            None => {
                                all_applied = false;
                                continue;
                            }
                        };
                        let st: Option<String> = db
                            .query_row(
                                "SELECT status FROM managed_agent_deployments
                             WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence=?3",
                                params![tenant, w, seq as i64],
                                |r| r.get(0),
                            )
                            .optional()?;
                        match st.as_deref() {
                            Some("rejected") => {
                                any_rejected = Some(w.clone());
                                break;
                            }
                            Some("applied") => {}
                            _ => {
                                all_applied = false;
                            }
                        }
                    }

                    if let Some(rejected_agent) = any_rejected {
                        let reason = format!(
                            "standard agent '{}' rejected candidate policy revision '{}'",
                            rejected_agent, revision
                        );
                        let mut to_rollback = Vec::new();
                        for (agent, _) in &active_deployments {
                            if let Some(Some(prev)) = previous_revisions.get(agent) {
                                to_rollback.push((agent.clone(), prev.clone()));
                            }
                        }
                        NextAction::Rollback {
                            rollout: base_rollout,
                            to_rollback,
                            reason,
                        }
                    } else if all_applied {
                        NextAction::Complete(base_rollout)
                    } else {
                        NextAction::StillRunning(base_rollout)
                    }
                }
                _ => NextAction::None,
            }
        };

        let now = now_unix();
        match action {
            NextAction::None => Ok(None),
            NextAction::StillRunning(r) => Ok(Some(r)),
            NextAction::Rollback {
                mut rollout,
                to_rollback,
                reason,
            } => {
                for (agent, prev) in to_rollback {
                    let _ = self.deploy_managed_revision(tenant, &agent, &prev, true, issuer);
                }
                let db = self.connection()?;
                db.execute(
                    "UPDATE managed_group_rollouts
                     SET phase='rolled_back', failure_reason=?3, updated_at_unix=?4
                     WHERE tenant_id=?1 AND group_id=?2 AND rollout_id=?5",
                    params![tenant, group_id, reason, now, rollout.rollout_id],
                )?;
                rollout.phase = RolloutPhase::RolledBack;
                rollout.failure_reason = Some(reason);
                rollout.updated_at_unix = now;
                Ok(Some(rollout))
            }
            NextAction::PromoteToStandard {
                mut rollout,
                standards,
                revision,
            } => {
                for w in standards {
                    let dep = self.deploy_managed_revision(tenant, &w, &revision, false, issuer)?;
                    rollout.active_deployments.insert(w, dep.deployment_sequence);
                }
                let db = self.connection()?;
                db.execute(
                    "UPDATE managed_group_rollouts
                     SET phase='standard', active_deployments_json=?3, updated_at_unix=?4
                     WHERE tenant_id=?1 AND group_id=?2 AND rollout_id=?5",
                    params![
                        tenant,
                        group_id,
                        serde_json::to_string(&rollout.active_deployments)?,
                        now,
                        rollout.rollout_id
                    ],
                )?;
                rollout.phase = RolloutPhase::Standard;
                rollout.updated_at_unix = now;
                Ok(Some(rollout))
            }
            NextAction::Complete(mut rollout) => {
                let db = self.connection()?;
                db.execute(
                    "UPDATE managed_group_rollouts
                     SET phase='completed', updated_at_unix=?3
                     WHERE tenant_id=?1 AND group_id=?2 AND rollout_id=?4",
                    params![tenant, group_id, now, rollout.rollout_id],
                )?;
                rollout.phase = RolloutPhase::Completed;
                rollout.updated_at_unix = now;
                Ok(Some(rollout))
            }
        }
    }

    pub fn get_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<ManagedGroupRollout>> {
        ensure!(exact_id(tenant) && exact_id(group_id), "invalid identifier");
        let db = self.connection()?;
        schema(&db)?;
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            i64,
            i64,
        )> = db
            .query_row(
                "SELECT rollout_id, revision, policy_sha256, issuer_key_id, phase,
                    pilot_agents_json, standard_agents_json, active_deployments_json,
                    previous_revisions_json, failure_reason, created_at_unix, updated_at_unix
             FROM managed_group_rollouts
             WHERE tenant_id=?1 AND group_id=?2
             ORDER BY created_at_unix DESC LIMIT 1",
                params![tenant, group_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            rollout_id,
            revision,
            policy_sha256,
            issuer_key_id,
            phase_str,
            pilot_json,
            standard_json,
            active_json,
            prev_json,
            failure_reason,
            created_at,
            updated_at,
        )) = row
        else {
            return Ok(None);
        };

        Ok(Some(ManagedGroupRollout {
            tenant_id: tenant.into(),
            group_id: group_id.into(),
            rollout_id,
            revision,
            policy_sha256,
            issuer_key_id,
            phase: phase_str.parse()?,
            pilot_agents: serde_json::from_str(&pilot_json)?,
            standard_agents: serde_json::from_str(&standard_json)?,
            active_deployments: serde_json::from_str(&active_json)?,
            previous_revisions: serde_json::from_str(&prev_json)?,
            failure_reason,
            created_at_unix: created_at,
            updated_at_unix: updated_at,
        }))
    }

    pub fn rollback_managed_group_rollout(
        &self,
        tenant: &str,
        group_id: &str,
        issuer: &ManagedIssuer,
    ) -> Result<Option<ManagedGroupRollout>> {
        let (mut rollout, to_rollback) = {
            let db = self.connection()?;
            schema(&db)?;
            let row: Option<(
                String,
                String,
                String,
                Option<String>,
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                i64,
                i64,
            )> = db
                .query_row(
                    "SELECT rollout_id, revision, policy_sha256, issuer_key_id, phase,
                        pilot_agents_json, standard_agents_json, active_deployments_json,
                        previous_revisions_json, failure_reason, created_at_unix, updated_at_unix
                 FROM managed_group_rollouts
                 WHERE tenant_id=?1 AND group_id=?2 AND phase IN ('pilot','standard')
                 ORDER BY created_at_unix DESC LIMIT 1",
                    params![tenant, group_id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                            r.get(9)?,
                            r.get(10)?,
                            r.get(11)?,
                        ))
                    },
                )
                .optional()?;

            let Some((
                rollout_id,
                revision,
                policy_sha256,
                issuer_key_id,
                _phase_str,
                pilot_json,
                standard_json,
                active_json,
                prev_json,
                _failure_reason,
                created_at,
                _updated_at,
            )) = row
            else {
                return Ok(None);
            };

            let pilot_agents: Vec<String> = serde_json::from_str(&pilot_json)?;
            let standard_agents: Vec<String> = serde_json::from_str(&standard_json)?;
            let active_deployments: std::collections::BTreeMap<String, u64> =
                serde_json::from_str(&active_json)?;
            let previous_revisions: std::collections::BTreeMap<String, Option<String>> =
                serde_json::from_str(&prev_json)?;

            let mut to_rollback = Vec::new();
            for (agent, _) in &active_deployments {
                if let Some(Some(prev)) = previous_revisions.get(agent) {
                    to_rollback.push((agent.clone(), prev.clone()));
                }
            }

            let r = ManagedGroupRollout {
                tenant_id: tenant.into(),
                group_id: group_id.into(),
                rollout_id,
                revision,
                policy_sha256,
                issuer_key_id,
                phase: RolloutPhase::RolledBack,
                pilot_agents,
                standard_agents,
                active_deployments,
                previous_revisions,
                failure_reason: Some("operator requested rollback".to_string()),
                created_at_unix: created_at,
                updated_at_unix: now_unix(),
            };
            (r, to_rollback)
        };

        for (agent, prev) in to_rollback {
            let _ = self.deploy_managed_revision(tenant, &agent, &prev, true, issuer);
        }

        let now = now_unix();
        let reason = "operator requested rollback".to_string();
        {
            let db = self.connection()?;
            db.execute(
                "UPDATE managed_group_rollouts
                 SET phase='rolled_back', failure_reason=?3, updated_at_unix=?4
                 WHERE tenant_id=?1 AND group_id=?2 AND rollout_id=?5",
                params![tenant, group_id, reason, now, rollout.rollout_id],
            )?;
        }
        rollout.updated_at_unix = now;
        Ok(Some(rollout))
    }

    pub fn check_and_advance_active_rollouts_for_agent(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<()> {
        let group_ids = {
            let db = self.connection()?;
            schema(&db)?;
            let mut stmt = db.prepare(
                "SELECT DISTINCT m.group_id FROM managed_agent_group_members m
                 JOIN managed_group_rollouts r ON r.tenant_id=m.tenant_id AND r.group_id=m.group_id
                 WHERE m.tenant_id=?1 AND m.agent_id=?2 AND r.phase IN ('pilot','standard')",
            )?;
            let ids = stmt
                .query_map(params![tenant, agent], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ids
        };

        for gid in group_ids {
            let issuer_key_id: Option<String> = {
                let db = self.connection()?;
                db.query_row(
                    "SELECT issuer_key_id FROM managed_group_rollouts
                 WHERE tenant_id=?1 AND group_id=?2 AND phase IN ('pilot','standard')
                 ORDER BY created_at_unix DESC LIMIT 1",
                    params![tenant, gid],
                    |r| r.get(0),
                )
                .optional()?
                .flatten()
            };

            if let Ok(issuer) =
                ManagedIssuer::from_environment_for_key(issuer_key_id.as_deref())
            {
                let _ = self.advance_managed_group_rollout(tenant, &gid, &issuer);
            }
        }
        Ok(())
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

    #[test]
    fn test_group_lifecycle_membership_and_revisions() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("group-tenant").unwrap();
        store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
        store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();

        // 1. Create group
        let group = store
            .create_managed_group(&tenant.id, "prod-agents", "Production Agents")
            .unwrap();
        assert_eq!(group.group_id, "prod-agents");
        assert_eq!(group.name, "Production Agents");

        // 2. Add members: pilot and standard
        let m1 = store
            .add_managed_group_member(&tenant.id, "prod-agents", "pilot-1", true)
            .unwrap();
        assert!(m1.is_pilot);
        let m2 = store
            .add_managed_group_member(&tenant.id, "prod-agents", "worker-1", false)
            .unwrap();
        assert!(!m2.is_pilot);

        let members = store
            .list_managed_group_members(&tenant.id, "prod-agents")
            .unwrap();
        assert_eq!(members.len(), 2);

        // 3. Group revisions
        let rev = store
            .create_managed_group_revision(
                &tenant.id,
                "prod-agents",
                "v1",
                "default: deny\n",
            )
            .unwrap();
        assert_eq!(rev.revision, "v1");
        assert!(!rev.approved);

        assert!(store
            .approve_managed_group_revision(&tenant.id, "prod-agents", "v1")
            .unwrap());
    }

    #[test]
    fn test_staged_group_rollout_pilot_success_promotes_to_standard() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("rollout-tenant").unwrap();
        store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
        store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();

        store
            .create_managed_group(&tenant.id, "cluster-a", "Cluster A")
            .unwrap();
        store
            .add_managed_group_member(&tenant.id, "cluster-a", "pilot-1", true)
            .unwrap();
        store
            .add_managed_group_member(&tenant.id, "cluster-a", "worker-1", false)
            .unwrap();

        let signer = ManagedIssuer {
            key_id: "k1".into(),
            pair: Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap(),
        };

        // Baseline revision v1 deployed to both
        store
            .create_managed_group_revision(
                &tenant.id,
                "cluster-a",
                "v1",
                "default: deny\n",
            )
            .unwrap();
        store
            .approve_managed_group_revision(&tenant.id, "cluster-a", "v1")
            .unwrap();

        // Target candidate revision v2
        store
            .create_managed_group_revision(
                &tenant.id,
                "cluster-a",
                "v2",
                "default: allow\n",
            )
            .unwrap();
        store
            .approve_managed_group_revision(&tenant.id, "cluster-a", "v2")
            .unwrap();

        // Start rollout
        let ro = store
            .start_managed_group_rollout(&tenant.id, "cluster-a", "v2", &signer)
            .unwrap();
        assert_eq!(ro.phase, RolloutPhase::Pilot);
        assert_eq!(ro.pilot_agents, vec!["pilot-1"]);
        assert_eq!(ro.standard_agents, vec!["worker-1"]);

        // Pilot received v2 deployment
        let p_bundle = store
            .deliver_managed_bundle(&tenant.id, "pilot-1")
            .unwrap()
            .unwrap();
        assert_eq!(p_bundle.revision, "v2");
        // Worker did NOT receive v2 deployment yet
        let w_bundle = store
            .deliver_managed_bundle(&tenant.id, "worker-1")
            .unwrap();
        assert!(w_bundle.is_none());

        // Pilot acknowledges applied
        store
            .acknowledge_managed_bundle(
                &tenant.id,
                "pilot-1",
                &AppliedReport {
                    deployment_sequence: p_bundle.deployment_sequence,
                    revision: "v2".into(),
                    policy_sha256: p_bundle.policy_sha256.clone(),
                    status: "applied".into(),
                },
            )
            .unwrap();

        // Advance rollout
        let advanced = store
            .advance_managed_group_rollout(&tenant.id, "cluster-a", &signer)
            .unwrap()
            .unwrap();
        assert_eq!(advanced.phase, RolloutPhase::Standard);

        // Now worker receives v2 deployment
        let w_bundle = store
            .deliver_managed_bundle(&tenant.id, "worker-1")
            .unwrap()
            .unwrap();
        assert_eq!(w_bundle.revision, "v2");

        // Worker acknowledges applied
        store
            .acknowledge_managed_bundle(
                &tenant.id,
                "worker-1",
                &AppliedReport {
                    deployment_sequence: w_bundle.deployment_sequence,
                    revision: "v2".into(),
                    policy_sha256: w_bundle.policy_sha256.clone(),
                    status: "applied".into(),
                },
            )
            .unwrap();

        let finished = store
            .advance_managed_group_rollout(&tenant.id, "cluster-a", &signer)
            .unwrap()
            .unwrap();
        assert_eq!(finished.phase, RolloutPhase::Completed);
    }

    #[test]
    fn test_staged_group_rollout_pilot_rejection_auto_rollbacks_and_spares_standard() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("rollback-tenant").unwrap();
        store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
        store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();

        store
            .create_managed_group(&tenant.id, "cluster-b", "Cluster B")
            .unwrap();
        store
            .add_managed_group_member(&tenant.id, "cluster-b", "pilot-1", true)
            .unwrap();
        store
            .add_managed_group_member(&tenant.id, "cluster-b", "worker-1", false)
            .unwrap();

        let signer = ManagedIssuer {
            key_id: "k1".into(),
            pair: Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap(),
        };

        // Deploy initial baseline v1 to pilot-1
        store
            .create_managed_revision(&tenant.id, "pilot-1", "v1", "default: allow\n")
            .unwrap();
        store
            .approve_managed_revision(&tenant.id, "pilot-1", "v1")
            .unwrap();
        let p_v1 = store
            .deploy_managed_revision(&tenant.id, "pilot-1", "v1", false, &signer)
            .unwrap();
        store
            .deliver_managed_bundle(&tenant.id, "pilot-1")
            .unwrap();
        store
            .acknowledge_managed_bundle(
                &tenant.id,
                "pilot-1",
                &AppliedReport {
                    deployment_sequence: p_v1.deployment_sequence,
                    revision: "v1".into(),
                    policy_sha256: p_v1.policy_sha256.clone(),
                    status: "applied".into(),
                },
            )
            .unwrap();

        // Candidate revision v2 on group
        store
            .create_managed_group_revision(
                &tenant.id,
                "cluster-b",
                "v2",
                "default: deny\n",
            )
            .unwrap();
        store
            .approve_managed_group_revision(&tenant.id, "cluster-b", "v2")
            .unwrap();

        let ro = store
            .start_managed_group_rollout(&tenant.id, "cluster-b", "v2", &signer)
            .unwrap();
        assert_eq!(ro.phase, RolloutPhase::Pilot);

        // Pilot delivers bundle and REJECTS it
        let p_bundle = store
            .deliver_managed_bundle(&tenant.id, "pilot-1")
            .unwrap()
            .unwrap();
        assert_eq!(p_bundle.revision, "v2");

        store
            .acknowledge_managed_bundle(
                &tenant.id,
                "pilot-1",
                &AppliedReport {
                    deployment_sequence: p_bundle.deployment_sequence,
                    revision: "v2".into(),
                    policy_sha256: p_bundle.policy_sha256.clone(),
                    status: "rejected".into(),
                },
            )
            .unwrap();

        // Advance rollout: should detect rejection, trigger rollback to v1, set phase = RolledBack
        let ro_after = store
            .advance_managed_group_rollout(&tenant.id, "cluster-b", &signer)
            .unwrap()
            .unwrap();
        assert_eq!(ro_after.phase, RolloutPhase::RolledBack);
        assert!(ro_after.failure_reason.unwrap().contains("rejected"));

        // Pilot now has a rollback deployment for v1 with higher sequence!
        let rollback_bundle = store
            .deliver_managed_bundle(&tenant.id, "pilot-1")
            .unwrap()
            .unwrap();
        assert_eq!(rollback_bundle.revision, "v1");
        assert!(rollback_bundle.deployment_sequence > p_bundle.deployment_sequence);

        // Worker was NEVER deployed candidate v2
        let worker_deployments = store
            .list_managed_deployments(&tenant.id, "worker-1")
            .unwrap();
        assert!(worker_deployments.is_empty());
    }
}

