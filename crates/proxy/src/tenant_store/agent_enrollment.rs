// SPDX-License-Identifier: Apache-2.0
//! SQLite-only, tenant-scoped managed Agent enrollment (SOU-30).
//!
//! Agent credentials are random, returned once, and hashed with domain
//! separation. They are never admin, tenant proxy, or workspace credentials.
//! A revoked Agent is rejected at lookup time even if it knows its old token.

use anyhow::{ensure, Context, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{now_unix, random_base64url, TenantStore};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnrolledAgent {
    pub tenant_id: String,
    pub agent_id: String,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
    /// Non-secret compare-and-swap generation, visible in admin inventory.
    pub credential_generation: i64,
}

/// Token is sent to the operator at enrollment ONLY. It must not be persisted
/// in a console log, audit event or ordinary agent inventory response.
#[derive(Serialize)]
pub struct IssuedAgentCredential {
    #[serde(flatten)]
    pub agent: EnrolledAgent,
    pub token: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRequest {
    pub expected_generation: i64,
    pub operation_id: String,
    pub replacement_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RotationOutcome {
    pub tenant_id: String,
    pub agent_id: String,
    pub generation: i64,
    pub operation_id: String,
    pub already_applied: bool,
}

pub(super) fn validated_rotation(input: &RotationRequest) -> Result<Vec<u8>> {
    ensure!(
        input.expected_generation > 0 && input.expected_generation < i64::MAX,
        "invalid credential generation"
    );
    ensure!(
        input.operation_id.len() == 32
            && input
                .operation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid rotation operation identifier"
    );
    credential_hash(&input.replacement_token).context("invalid replacement credential")
}

type RotationRow = (Vec<u8>, i64, Option<String>, Option<i64>, Option<Vec<u8>>);

pub(super) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

pub(super) fn credential_hash(token: &str) -> Option<Vec<u8>> {
    if token.len() != 52
        || !token.starts_with("sw_agent_")
        || !token
            .bytes()
            .skip(9)
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"soup-wall-managed-agent-credential-v1\0");
    digest.update(token.as_bytes());
    Some(digest.finalize().to_vec())
}

fn ensure_schema(connection: &rusqlite::Connection) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS managed_agent_enrollments (
             tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
             agent_id TEXT NOT NULL,
             token_hash BLOB NOT NULL UNIQUE,
             created_at_unix INTEGER NOT NULL,
             revoked_at_unix INTEGER,
             credential_generation INTEGER NOT NULL DEFAULT 1 CHECK(credential_generation > 0),
             last_rotation_id TEXT,
             last_rotation_expected_generation INTEGER,
             last_rotation_digest BLOB,
             PRIMARY KEY (tenant_id, agent_id)
         );
         CREATE INDEX IF NOT EXISTS managed_agents_active_tokens
             ON managed_agent_enrollments(token_hash)
             WHERE revoked_at_unix IS NULL;",
        )
        .context("failed to prepare SQLite managed-agent enrollment schema")?;
    // Old SQLite enrollments were created without these columns. Only a caller
    // that observes an old schema takes the write lock; recheck after locking.
    let has_generation: bool = connection
        .prepare("PRAGMA table_info(managed_agent_enrollments)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|name| name == "credential_generation");
    if !has_generation {
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let migration = (|| -> Result<()> {
            let columns: Vec<String> = connection
                .prepare("PRAGMA table_info(managed_agent_enrollments)")?
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<_>>()?;
            for (name, sql) in [
                ("credential_generation", "ALTER TABLE managed_agent_enrollments ADD COLUMN credential_generation INTEGER NOT NULL DEFAULT 1 CHECK(credential_generation > 0)"),
                ("last_rotation_id", "ALTER TABLE managed_agent_enrollments ADD COLUMN last_rotation_id TEXT"),
                ("last_rotation_expected_generation", "ALTER TABLE managed_agent_enrollments ADD COLUMN last_rotation_expected_generation INTEGER"),
                ("last_rotation_digest", "ALTER TABLE managed_agent_enrollments ADD COLUMN last_rotation_digest BLOB"),
            ] {
                if !columns.iter().any(|column| column == name) {
                    connection.execute_batch(sql)?;
                }
            }
            Ok(())
        })();
        if migration.is_ok() {
            connection.execute_batch("COMMIT")?;
        } else {
            let _ = connection.execute_batch("ROLLBACK");
            migration?;
        }
    }
    Ok(())
}

impl TenantStore {
    /// Called by an authorized *admin* route, never directly by an Agent.
    /// A second enrollment for the same tenant/Agent is rejected; after
    /// revocation, reprovision a distinct Agent identity in this bounded slice.
    pub fn enroll_managed_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<IssuedAgentCredential> {
        ensure!(
            valid_id(tenant_id) && valid_id(agent_id),
            "invalid tenant/Agent identity"
        );
        let mut conn = self.connection()?;
        ensure_schema(&conn)?;
        let tx = conn
            .transaction()
            .context("could not start Agent enrollment transaction")?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT active FROM tenants WHERE id = ?1",
                [tenant_id],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(active == Some(1), "tenant not found or inactive");
        let token = format!("sw_agent_{}", random_base64url(32));
        let hash = credential_hash(&token).context("invalid generated Agent credential")?;
        let created_at_unix = now_unix();
        tx.execute(
            "INSERT INTO managed_agent_enrollments
                 (tenant_id, agent_id, token_hash, created_at_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![tenant_id, agent_id, hash, created_at_unix],
        )
        .context("Agent enrollment already exists or could not be saved")?;
        tx.commit()?;
        Ok(IssuedAgentCredential {
            agent: EnrolledAgent {
                tenant_id: tenant_id.to_owned(),
                agent_id: agent_id.to_owned(),
                created_at_unix,
                revoked_at_unix: None,
                credential_generation: 1,
            },
            token,
        })
    }

    /// Compare-and-swap rotation with a durable, non-secret retry receipt.
    /// Never resurrects revoked enrollments or overwrites concurrent rotations.
    pub fn rotate_managed_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        input: &RotationRequest,
    ) -> Result<RotationOutcome> {
        ensure!(
            valid_id(tenant_id) && valid_id(agent_id),
            "invalid identity"
        );
        let new_hash = validated_rotation(input)?;
        let mut conn = self.connection()?;
        ensure_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: Option<i64> = tx
            .query_row("SELECT active FROM tenants WHERE id=?1", [tenant_id], |r| {
                r.get(0)
            })
            .optional()?;
        ensure!(active == Some(1), "tenant absent or inactive");
        let current: Option<RotationRow> =
            tx.query_row(
                "SELECT token_hash,credential_generation,last_rotation_id,last_rotation_expected_generation,last_rotation_digest
                 FROM managed_agent_enrollments
                 WHERE tenant_id=?1 AND agent_id=?2 AND revoked_at_unix IS NULL",
                params![tenant_id, agent_id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))
            ).optional()?;
        let (old_hash, generation, last_id, last_generation, last_digest) =
            current.context("Agent absent or revoked")?;
        if last_id.as_deref() == Some(&input.operation_id)
            && last_generation == Some(input.expected_generation)
            && last_digest.as_deref() == Some(new_hash.as_slice())
        {
            return Ok(RotationOutcome {
                tenant_id: tenant_id.into(),
                agent_id: agent_id.into(),
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
        tx.execute(
            "UPDATE managed_agent_enrollments
             SET token_hash=?3,credential_generation=?4,last_rotation_id=?5,
                 last_rotation_expected_generation=?6,last_rotation_digest=?7
             WHERE tenant_id=?1 AND agent_id=?2 AND revoked_at_unix IS NULL",
            params![
                tenant_id,
                agent_id,
                new_hash,
                next,
                input.operation_id,
                input.expected_generation,
                new_hash
            ],
        )?;
        tx.commit()?;
        Ok(RotationOutcome {
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            generation: next,
            operation_id: input.operation_id.clone(),
            already_applied: false,
        })
    }

    /// Strictly Bearer Agent credential; tenant/admin tokens never work here.
    /// A disabled tenant and any revoked enrollment are refused.
    pub fn authenticate_managed_agent(
        &self,
        authorization: Option<&str>,
    ) -> Result<Option<EnrolledAgent>> {
        let Some(token) = authorization.and_then(|s| s.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        let Some(hash) = credential_hash(token) else {
            return Ok(None);
        };
        let conn = self.connection()?;
        ensure_schema(&conn)?;
        conn.query_row(
            "SELECT a.tenant_id, a.agent_id, a.created_at_unix, a.revoked_at_unix, a.credential_generation
             FROM managed_agent_enrollments a
             JOIN tenants t ON t.id = a.tenant_id
             WHERE a.token_hash = ?1 AND a.revoked_at_unix IS NULL AND t.active = 1",
            [hash],
            |r| {
                Ok(EnrolledAgent {
                    tenant_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    created_at_unix: r.get(2)?,
                    revoked_at_unix: r.get(3)?,
                    credential_generation: r.get(4)?,
                })
            },
        )
        .optional()
        .context("managed Agent authentication failed")
    }

    /// Revoking enrollment invalidates credential and fetch/ack authorization.
    pub fn revoke_managed_agent(&self, tenant_id: &str, agent_id: &str) -> Result<bool> {
        ensure!(
            valid_id(tenant_id) && valid_id(agent_id),
            "invalid tenant/Agent identity"
        );
        let conn = self.connection()?;
        ensure_schema(&conn)?;
        let changed = conn.execute(
            "UPDATE managed_agent_enrollments SET revoked_at_unix = ?3
             WHERE tenant_id = ?1 AND agent_id = ?2 AND revoked_at_unix IS NULL",
            params![tenant_id, agent_id, now_unix()],
        )?;
        Ok(changed == 1)
    }

    /// Bounded tenant-scoped inventory with no credential hashes or secrets.
    pub fn list_managed_agents(&self, tenant_id: &str) -> Result<Vec<EnrolledAgent>> {
        ensure!(valid_id(tenant_id), "invalid tenant identity");
        let conn = self.connection()?;
        ensure_schema(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT tenant_id, agent_id, created_at_unix, revoked_at_unix, credential_generation
             FROM managed_agent_enrollments WHERE tenant_id = ?1
             ORDER BY agent_id ASC LIMIT 256",
        )?;
        let rows = stmt.query_map([tenant_id], |r| {
            Ok(EnrolledAgent {
                tenant_id: r.get(0)?,
                agent_id: r.get(1)?,
                created_at_unix: r.get(2)?,
                revoked_at_unix: r.get(3)?,
                credential_generation: r.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list managed Agents")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_authenticate_revoke_and_isolate_tenants() {
        let store = TenantStore::open(":memory:").unwrap();
        let one = store.create_tenant("agent-enrollment-one").unwrap();
        let two = store.create_tenant("agent-enrollment-two").unwrap();
        let issued = store.enroll_managed_agent(&one.id, "agent-a").unwrap();
        assert!(issued.token.starts_with("sw_agent_"));
        assert!(store.enroll_managed_agent(&one.id, "agent-a").is_err());
        assert!(store
            .enroll_managed_agent("tenant_not_real", "agent-a")
            .is_err());
        assert!(store
            .authenticate_managed_agent(Some("Bearer llmfw_tenant_token"))
            .unwrap()
            .is_none());
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {}", issued.token)))
            .unwrap()
            .is_some());
        let list = store.list_managed_agents(&one.id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_id, "agent-a");
        assert!(store.list_managed_agents(&two.id).unwrap().is_empty());
        assert!(store.revoke_managed_agent(&one.id, "agent-a").unwrap());
        assert!(!store.revoke_managed_agent(&one.id, "agent-a").unwrap());
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {}", issued.token)))
            .unwrap()
            .is_none());
        assert!(store.list_managed_agents(&one.id).unwrap()[0]
            .revoked_at_unix
            .is_some());
    }

    #[test]
    fn rotate_is_atomic_idempotent_and_revokes_old_authentication() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("rotation-test").unwrap();
        let old = store.enroll_managed_agent(&tenant.id, "agent").unwrap();
        let new_token = format!("sw_agent_{}", random_base64url(32));
        let request = RotationRequest {
            expected_generation: 1,
            operation_id: "0123456789abcdef0123456789abcdef".into(),
            replacement_token: new_token.clone(),
        };
        let first = store
            .rotate_managed_agent(&tenant.id, "agent", &request)
            .unwrap();
        assert_eq!(first.generation, 2);
        assert!(!first.already_applied);
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {}", old.token)))
            .unwrap()
            .is_none());
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {new_token}")))
            .unwrap()
            .is_some());
        assert!(
            store
                .rotate_managed_agent(&tenant.id, "agent", &request)
                .unwrap()
                .already_applied
        );
        let stale = RotationRequest {
            operation_id: "abcdef0123456789abcdef0123456789".into(),
            ..request.clone()
        };
        assert!(store
            .rotate_managed_agent(&tenant.id, "agent", &stale)
            .is_err());
        assert!(store.revoke_managed_agent(&tenant.id, "agent").unwrap());
        assert!(store
            .rotate_managed_agent(&tenant.id, "agent", &request)
            .is_err());
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {new_token}")))
            .unwrap()
            .is_none());
    }

    #[test]
    fn validate_agent_identity_rejects_paths_and_empty_ids() {
        assert!(!valid_id(""));
        assert!(!valid_id("../../x"));
        assert!(!valid_id("white space"));
        assert!(!valid_id(&"a".repeat(129)));
        assert!(valid_id("agent.alpha-01"));
    }
}
